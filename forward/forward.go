package forward

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// ErrNoUpstream is returned by New when no upstream Exchanger has been
// configured.
var ErrNoUpstream = errors.New("forward: no upstream configured")

// ErrInflightFull is returned when a cache miss arrives while the
// configured WithMaxInflight cap is saturated. Surfaces as SERVFAIL
// to the inbound peer.
var ErrInflightFull = errors.New("forward: max inflight upstream calls reached")

// Compile-time assertion that *Forwarder satisfies acidns.Handler.
// Renamed from Handler to Forwarder so the type does not shadow the
// root package's Handler interface at use sites.
var _ acidns.Handler = (*Forwarder)(nil)

// Forwarder is the caching forwarder. It is safe for concurrent use by
// multiple goroutines: ServeDNS serialises cache reads/writes internally
// and the configured upstream Exchanger is required to be concurrency-safe
// (see acidns.Exchanger).
type Forwarder struct {
	cfg   config
	cache *cache

	// inflight coalesces concurrent cache misses for the same
	// (name, type, class). Without this, a thundering herd on a cold
	// cache key would multiply outbound query volume one-for-one with
	// inbound; with it, only one goroutine talks to the upstream and
	// the rest reuse its result.
	inflightMu sync.Mutex
	inflight   map[string]*inflightCall
	// inflightSem is a counting semaphore bounding the pool of distinct
	// outbound upstream goroutines. nil when WithMaxInflight ≤ 0.
	inflightSem chan struct{}

	// closeOnce guards Close so it is idempotent — repeated calls
	// observe the same upstream-Close error without re-invoking it.
	closeOnce sync.Once
	closeErr  error
	// closed is set after Close returns; ServeDNS observes this and
	// replies SERVFAIL rather than driving a now-dead upstream.
	closed atomic.Bool
}

type inflightCall struct {
	done chan struct{}
	resp wire.Message
	err  error
}

// New returns a Forwarder. Exactly one of WithUpstream, WithUDPUpstream,
// or WithDoTUpstream must be supplied.
func New(opts ...Option) (*Forwarder, error) {
	c := config{
		cacheSize:    4096,
		minTTL:       0,
		maxTTL:       24 * time.Hour,
		maxNegTTL:    5 * time.Minute,
		queryTimeout: 5 * time.Second,
		maxInflight:  1024,
		now:          time.Now,
	}
	for _, o := range opts {
		o.applyForward(&c)
	}
	if c.upstream == nil {
		return nil, ErrNoUpstream
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.logger == nil {
		c.logger = slog.New(slog.DiscardHandler)
	}
	h := &Forwarder{cfg: c, cache: newCache(c.cacheSize), inflight: make(map[string]*inflightCall)}
	if c.maxInflight > 0 {
		h.inflightSem = make(chan struct{}, c.maxInflight)
	}
	return h, nil
}

// UpstreamName reports a human-readable description of the configured
// upstream — useful for startup logs and metrics labels.
func (h *Forwarder) UpstreamName() string { return h.cfg.upstreamName }

// CacheSize returns the current number of entries in the cache.
func (h *Forwarder) CacheSize() int { return h.cache.len() }

// Close drops the cache and, if the configured upstream Exchanger
// implements io.Closer, propagates the Close call to it. Subsequent
// ServeDNS calls reply SERVFAIL rather than dispatch to the (now
// possibly closed) upstream; in-flight ServeDNS goroutines that
// passed the closed check before Close fired will continue to use
// the upstream until they complete.
//
// Close is idempotent — repeated calls return the same upstream
// Close error (nil if the upstream does not implement io.Closer).
func (h *Forwarder) Close() error {
	h.closeOnce.Do(func() {
		h.closed.Store(true)
		h.cache.clear()
		if c, ok := h.cfg.upstream.(io.Closer); ok {
			h.closeErr = c.Close()
		}
	})
	return h.closeErr
}

// ServeDNS answers q by serving from cache when fresh, otherwise by
// forwarding to the configured upstream and caching the result.
func (h *Forwarder) ServeDNS(ctx context.Context, w acidns.ResponseWriter, q wire.Message) {
	start := time.Now()
	if h.closed.Load() {
		_ = w.WriteMsg(buildErrorResponse(q, wire.RCODEServFail))
		h.cfg.logger.LogAttrs(ctx, slog.LevelDebug, "forward.serve",
			slog.String("decision", "closed"),
			slog.Duration("elapsed", time.Since(start)))
		return
	}
	// Framework-level ingress filters: drop QR=1 datagrams, FORMERR
	// on QDCOUNT≠1. The transport layer normally applies these, but
	// programmatic callers that invoke ServeDNS directly (tests,
	// composed handler chains, in-process pipelines) bypass the
	// transport — apply the gate here so the forwarder is safe to
	// embed without re-implementing it.
	switch verdict, reply := acidns.PreflightRequest(q); verdict {
	case acidns.PreflightDrop:
		h.cfg.logger.LogAttrs(ctx, slog.LevelDebug, "forward.serve",
			slog.String("decision", "drop_qr_set"),
			slog.Duration("elapsed", time.Since(start)))
		return
	case acidns.PreflightReply:
		if reply != nil {
			_ = w.WriteMsg(reply)
		}
		h.cfg.logger.LogAttrs(ctx, slog.LevelDebug, "forward.serve",
			slog.String("decision", "preflight_reply"),
			slog.Duration("elapsed", time.Since(start)))
		return
	}
	if q.Flags().Opcode() != wire.OpcodeQuery {
		_ = w.WriteMsg(buildErrorResponse(q, wire.RCODENotImp))
		h.cfg.logger.LogAttrs(ctx, slog.LevelDebug, "forward.serve",
			slog.String("decision", "notimp"),
			slog.Duration("elapsed", time.Since(start)))
		return
	}
	// A caching forwarder that answers RD=0 is an amplification
	// primitive — any peer can pull cached records without proving
	// they wanted recursion. Refuse such queries by default; an
	// operator that intentionally publishes the cache to non-recursive
	// peers can opt in via WithAllowNoRD.
	if !q.Flags().RecursionDesired() && !h.cfg.allowNoRD {
		_ = w.WriteMsg(buildErrorResponse(q, wire.RCODERefused))
		h.cfg.logger.LogAttrs(ctx, slog.LevelDebug, "forward.serve",
			slog.String("decision", "rd_required"),
			slog.Duration("elapsed", time.Since(start)))
		return
	}

	qq := q.Questions()[0]
	now := h.cfg.now()

	if e, ok := h.cache.get(qq.Name(), qq.Type(), qq.Class(), now); ok {
		_ = w.WriteMsg(buildFromCache(q, e, now))
		h.cfg.logger.LogAttrs(ctx, slog.LevelDebug, "forward.serve",
			slog.String("decision", "cache_hit"),
			slog.String("name", qq.Name().String()),
			slog.String("type", qq.Type().String()),
			slog.String("rcode", e.rcode.String()),
			slog.Duration("elapsed", time.Since(start)))
		return
	}

	resp, err := h.exchangeSingleflight(ctx, q, qq)
	if err != nil {
		_ = w.WriteMsg(buildErrorResponse(q, wire.RCODEServFail))
		h.cfg.logger.LogAttrs(ctx, slog.LevelError, "forward.serve",
			slog.String("decision", "upstream_error"),
			slog.String("name", qq.Name().String()),
			slog.String("type", qq.Type().String()),
			slog.String("upstream", h.cfg.upstreamName),
			slog.String("error", err.Error()),
			slog.Duration("elapsed", time.Since(start)))
		return
	}

	resp = filterBailiwick(qq.Name(), resp)
	if e, ok := makeEntry(resp, h.cfg, h.cfg.now()); ok {
		h.cache.put(qq.Name(), qq.Type(), qq.Class(), e)
	}

	_ = w.WriteMsg(rebuildForClient(q, resp))
	h.cfg.logger.LogAttrs(ctx, slog.LevelDebug, "forward.serve",
		slog.String("decision", "forwarded"),
		slog.String("name", qq.Name().String()),
		slog.String("type", qq.Type().String()),
		slog.String("upstream", h.cfg.upstreamName),
		slog.String("rcode", resp.Flags().RCODE().String()),
		slog.Duration("elapsed", time.Since(start)))
}

// exchangeSingleflight wraps the upstream Exchange call with
// per-(name,type,class) coalescing so concurrent cache misses don't
// multiply outbound query traffic. Every caller — including the one
// that allocated the inflight entry — is a waiter on call.done, and
// a dedicated goroutine drives the upstream Exchange under a context
// detached from any individual caller. This keeps follower waiters
// from being orphaned when the leader's request ctx fires before the
// upstream answer arrives, and gives the leader the same prompt-
// cancel semantics the followers already enjoyed.
func (h *Forwarder) exchangeSingleflight(ctx context.Context, in wire.Message, qq wire.Question) (wire.Message, error) {
	key := singleflightKey(qq, edsoDOBit(in))

	h.inflightMu.Lock()
	call, ok := h.inflight[key]
	if !ok {
		// Try to acquire a slot in the inflight semaphore before
		// publishing a new call entry. Fail fast on saturation rather
		// than queueing — queuing would let an attacker pin a deeper
		// resource pool by sustaining the burst.
		if h.inflightSem != nil {
			select {
			case h.inflightSem <- struct{}{}:
			default:
				h.inflightMu.Unlock()
				return nil, ErrInflightFull
			}
		}
		call = &inflightCall{done: make(chan struct{})}
		h.inflight[key] = call
		h.startExchange(ctx, call, key, in)
	}
	h.inflightMu.Unlock()

	select {
	case <-call.done:
		return call.resp, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// startExchange spawns the upstream Exchange goroutine for the given
// inflight call. The goroutine's context detaches the caller's
// cancellation via [context.WithoutCancel] (so a cancelled leader does
// not abort an in-flight upstream call that other waiters still need)
// while preserving caller-installed values — slog correlation ids,
// trace spans, etc. — for observers down the upstream stack. The
// exchange is bounded by queryTimeout when configured.
func (h *Forwarder) startExchange(callerCtx context.Context, call *inflightCall, key string, in wire.Message) {
	go func() {
		defer func() {
			h.inflightMu.Lock()
			delete(h.inflight, key)
			h.inflightMu.Unlock()
			if h.inflightSem != nil {
				<-h.inflightSem
			}
			close(call.done)
		}()
		exchangeCtx, cancel := context.WithCancel(context.WithoutCancel(callerCtx))
		defer cancel()
		if h.cfg.queryTimeout > 0 {
			var c2 context.CancelFunc
			exchangeCtx, c2 = context.WithTimeout(exchangeCtx, h.cfg.queryTimeout)
			defer c2()
		}
		fwd := buildForwardQuery(in)
		call.resp, call.err = h.cfg.upstream.Exchange(exchangeCtx, fwd)
	}()
}

// singleflightKey identifies a coalescable upstream call. Includes
// the DO bit so a DO=1 waiter (DNSSEC-aware client) does not silently
// receive a leader response that lacks DNSSEC RRs because the leader
// was built without DO=1. The two outcomes of an upstream are
// genuinely different responses; treating them as one would let the
// resolver above us cache the wrong shape.
func singleflightKey(qq wire.Question, doBit bool) string {
	suffix := "|0"
	if doBit {
		suffix = "|1"
	}
	return string(qq.Name().AppendWire(nil)) + "|" + qq.Type().String() + "|" + qq.Class().String() + suffix
}

// edsoDOBit returns the DO (DNSSEC OK) bit from the inbound query's
// OPT pseudo-RR, or false when the message has no OPT.
func edsoDOBit(q wire.Message) bool {
	e, ok := q.EDNS()
	if !ok || e == nil {
		return false
	}
	return e.DO()
}

// buildForwardQuery returns a fresh query carrying the same question and
// recursion-desired bit as the inbound q, with a freshly-randomised ID.
// DNSSEC-relevant EDNS state (DO bit, UDPSize, version) is preserved so
// DNSSEC-aware clients continue to receive RRSIGs from the upstream.
//
// EDNS handling on the inbound→upstream path is allow-list-by-default:
// only options known to be safe to forward are passed through. Every
// other option is stripped because a permissive deny-list (the previous
// "strip ECS and Cookie, forward everything else" shape) becomes a
// privacy regression every time IANA registers a new identifying
// option (RFC 7871 §7.1.2 nominates ECS specifically; the same logic
// applies to any future option that carries client-installed state).
//
// The default safe set is the protocol-mechanical options whose
// content does not identify the inbound client:
//
//   - Padding (RFC 7830 — covering message length)
//   - Edns-TCP-Keepalive (RFC 7828 — TCP-channel signalling)
//   - DAU/DHU/N3U (RFC 6975 — DNSSEC algorithm signalling)
//   - Extended DNS Errors (RFC 8914 — diagnostic; received from upstream)
//
// Cookies are minted per-channel and not forwarded; ECS is stripped
// per RFC 7871 §7.1.2.
func buildForwardQuery(q wire.Message) wire.Message {
	id, _ := newID()
	b := wire.NewBuilder().
		ID(id).
		RecursionDesired(true).
		CheckingDisabled(q.Flags().CheckingDisabled())
	for _, qq := range q.Questions() {
		b = b.Question(qq)
	}
	if e, ok := q.EDNS(); ok {
		eb := wire.NewEDNSBuilder().
			UDPSize(e.UDPSize()).
			ExtendedRCODE(e.ExtendedRCODE()).
			Version(e.Version()).
			DO(e.DO())
		for _, o := range e.Options() {
			if !isForwardSafeEDNSOption(o.Code()) {
				continue
			}
			eb = eb.Option(o)
		}
		ed, err := eb.Build()
		if err == nil {
			b = b.EDNS(ed)
		}
	}
	m, _ := b.Build()
	return m
}

// isForwardSafeEDNSOption reports whether an inbound EDNS option may
// flow through to the upstream resolver. Allow-list rather than
// deny-list — see [buildForwardQuery] doc.
func isForwardSafeEDNSOption(code uint16) bool {
	switch code {
	case wire.EDNSOptionPadding,
		wire.EDNSOptionTCPKeepalive,
		wire.EDNSOptionDAU,
		wire.EDNSOptionDHU,
		wire.EDNSOptionN3U,
		wire.EDNSOptionExtendedDNS:
		return true
	}
	return false
}

// rebuildForClient stamps the upstream response with the inbound query's
// ID, ensures the response/recursion-available bits are set, and clears
// the authoritative-answer bit (a recursive-style answer is never
// authoritative).
func rebuildForClient(in, resp wire.Message) wire.Message {
	b := wire.NewBuilder().
		ID(in.ID()).
		Response(true).
		RecursionDesired(in.Flags().RecursionDesired()).
		RecursionAvailable(true).
		CheckingDisabled(in.Flags().CheckingDisabled()).
		AuthenticData(resp.Flags().AuthenticData()).
		RCODE(resp.Flags().RCODE())
	for _, qq := range in.Questions() {
		b = b.Question(qq)
	}
	for _, r := range resp.Answers() {
		b = b.Answer(r)
	}
	for _, r := range resp.Authorities() {
		b = b.Authority(r)
	}
	for _, r := range resp.Additionals() {
		b = b.Additional(r)
	}
	if e, ok := resp.EDNS(); ok {
		b = b.EDNS(e)
	}
	m, _ := b.Build()
	return m
}

// buildFromCache constructs a fresh response using the cached records,
// adjusting each TTL by the time elapsed since the entry was cached.
func buildFromCache(in wire.Message, e entry, now time.Time) wire.Message {
	elapsed := now.Sub(e.insertedAt)
	b := wire.NewBuilder().
		ID(in.ID()).
		Response(true).
		RecursionDesired(in.Flags().RecursionDesired()).
		RecursionAvailable(true).
		CheckingDisabled(in.Flags().CheckingDisabled()).
		AuthenticData(e.ad).
		RCODE(e.rcode)
	for _, qq := range in.Questions() {
		b = b.Question(qq)
	}
	for _, r := range e.answers {
		b = b.Answer(adjustTTL(r, elapsed))
	}
	for _, r := range e.authority {
		b = b.Authority(adjustTTL(r, elapsed))
	}
	for _, r := range e.additional {
		b = b.Additional(adjustTTL(r, elapsed))
	}
	m, _ := b.Build()
	return m
}

// adjustTTL returns r with its TTL reduced by elapsed, floored at 0.
func adjustTTL(r wire.Record, elapsed time.Duration) wire.Record {
	remaining := max(r.TTL()-elapsed, 0)
	return wire.NewRecordClass(r.Name(), r.Class(), remaining, r.RData())
}

// makeEntry decides whether resp is cacheable, and if so returns the
// entry whose expiresAt encodes the joint TTL ceiling.
//
// Positive answers (NoError with answers) cache for the minimum TTL
// across the answer/authority sections, clamped to [minTTL, maxTTL].
// NXDOMAIN and NoData responses cache per RFC 2308 §5: TTL is the lower
// of the SOA MINIMUM (when an apex SOA appears in authority) and the
// SOA's own record TTL, then capped at maxNegTTL.
//
// Responses with RCODE other than NoError or NXDOMAIN, or NoError
// responses with no answers and no SOA, are not cached.
func makeEntry(resp wire.Message, cfg config, now time.Time) (entry, bool) {
	rcode := resp.Flags().RCODE()
	answers := resp.Answers()
	authority := resp.Authorities()
	additional := resp.Additionals()

	switch rcode {
	case wire.RCODENoError:
		if len(answers) > 0 {
			ttl := minTTL(answers, authority)
			ttl = clamp(ttl, cfg.minTTL, cfg.maxTTL)
			if ttl <= 0 {
				return entry{}, false
			}
			return entry{
				answers:    cloneRecs(answers),
				authority:  cloneRecs(authority),
				additional: cloneRecs(additional),
				rcode:      rcode,
				ad:         resp.Flags().AuthenticData(),
				insertedAt: now,
				expiresAt:  now.Add(ttl),
			}, true
		}
		// NoData: cache only if the upstream supplied a SOA in authority.
		ttl, ok := negativeTTLFromSOA(authority, cfg.maxNegTTL)
		if !ok {
			return entry{}, false
		}
		return entry{
			authority:  cloneRecs(authority),
			additional: cloneRecs(additional),
			rcode:      rcode,
			ad:         resp.Flags().AuthenticData(),
			insertedAt: now,
			expiresAt:  now.Add(ttl),
		}, true
	case wire.RCODENXDomain:
		ttl, ok := negativeTTLFromSOA(authority, cfg.maxNegTTL)
		if !ok {
			ttl = cfg.maxNegTTL
		}
		return entry{
			authority:  cloneRecs(authority),
			additional: cloneRecs(additional),
			rcode:      rcode,
			ad:         resp.Flags().AuthenticData(),
			insertedAt: now,
			expiresAt:  now.Add(ttl),
		}, true
	default:
		return entry{}, false
	}
}

// negativeTTLFromSOA extracts the RFC 2308 §5 negative-cache TTL from
// the authority section: min(SOA.MINIMUM, SOA.TTL), capped at maxNeg.
// Returns false if the authority section has no SOA.
func negativeTTLFromSOA(authority []wire.Record, maxNeg time.Duration) (time.Duration, bool) {
	for _, r := range authority {
		if r.Type() != rrtype.SOA {
			continue
		}
		soa, ok := r.RData().(rdata.SOA)
		if !ok {
			continue
		}
		ttl := min(min(r.TTL(), soa.Minimum()), maxNeg)
		if ttl <= 0 {
			return 0, false
		}
		return ttl, true
	}
	return 0, false
}

func minTTL(sets ...[]wire.Record) time.Duration {
	smallest := time.Duration(-1)
	for _, s := range sets {
		for _, r := range s {
			if smallest < 0 || r.TTL() < smallest {
				smallest = r.TTL()
			}
		}
	}
	if smallest < 0 {
		return 0
	}
	return smallest
}

func clamp(v, lo, hi time.Duration) time.Duration {
	if v < lo {
		v = lo
	}
	if hi > 0 && v > hi {
		v = hi
	}
	return v
}

func cloneRecs(s []wire.Record) []wire.Record {
	if len(s) == 0 {
		return nil
	}
	out := make([]wire.Record, len(s))
	copy(out, s)
	return out
}

func buildErrorResponse(q wire.Message, code wire.RCODE) wire.Message {
	b := wire.NewBuilder().
		ID(q.ID()).
		Response(true).
		RecursionDesired(q.Flags().RecursionDesired()).
		RecursionAvailable(true).
		RCODE(code)
	for _, qq := range q.Questions() {
		b = b.Question(qq)
	}
	m, _ := b.Build()
	return m
}

func newID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("forward: random id: %w", err)
	}
	return binary.BigEndian.Uint16(b[:]), nil
}
