package forward

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// ErrNoUpstream is returned by New when no upstream Exchanger has been
// configured.
var ErrNoUpstream = errors.New("forward: no upstream configured")

// Handler is the caching forwarder. It is safe for concurrent use by
// multiple goroutines: ServeDNS serialises cache reads/writes internally
// and the configured upstream Exchanger is required to be concurrency-safe
// (see acidns.Exchanger).
type Handler struct {
	cfg   config
	cache *cache
}

// New returns a Handler. Exactly one of WithUpstream, WithUDPUpstream,
// or WithDoTUpstream must be supplied.
func New(opts ...Option) (*Handler, error) {
	c := config{
		cacheSize:    4096,
		minTTL:       0,
		maxTTL:       24 * time.Hour,
		maxNegTTL:    5 * time.Minute,
		queryTimeout: 5 * time.Second,
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
	return &Handler{cfg: c, cache: newCache(c.cacheSize)}, nil
}

// UpstreamName reports a human-readable description of the configured
// upstream — useful for startup logs and metrics labels.
func (h *Handler) UpstreamName() string { return h.cfg.upstreamName }

// CacheSize returns the current number of entries in the cache.
func (h *Handler) CacheSize() int { return h.cache.len() }

// Close drops the cache and, if the configured upstream Exchanger
// implements io.Closer, propagates the Close call to it. Callers SHOULD
// stop sending queries through the handler before calling Close: any
// in-flight ServeDNS goroutine will continue to use the (now possibly
// closed) upstream until it completes.
//
// Returns the upstream's Close error, or nil if the upstream does not
// implement io.Closer.
func (h *Handler) Close() error {
	h.cache.clear()
	if c, ok := h.cfg.upstream.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// ServeDNS answers q by serving from cache when fresh, otherwise by
// forwarding to the configured upstream and caching the result.
func (h *Handler) ServeDNS(ctx context.Context, w acidns.ResponseWriter, q wire.Message) {
	start := time.Now()
	if q.Flags().Opcode() != wire.OpcodeQuery {
		_ = w.WriteMsg(buildErrorResponse(q, wire.RCODENotImp))
		h.cfg.logger.LogAttrs(ctx, slog.LevelDebug, "forward.serve",
			slog.String("decision", "notimp"),
			slog.Duration("elapsed", time.Since(start)))
		return
	}
	if len(q.Questions()) != 1 {
		_ = w.WriteMsg(buildErrorResponse(q, wire.RCODEFormErr))
		h.cfg.logger.LogAttrs(ctx, slog.LevelDebug, "forward.serve",
			slog.String("decision", "formerr"),
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

	fwd := buildForwardQuery(q)
	exchangeCtx := ctx
	if _, ok := ctx.Deadline(); !ok && h.cfg.queryTimeout > 0 {
		var cancel context.CancelFunc
		exchangeCtx, cancel = context.WithTimeout(ctx, h.cfg.queryTimeout)
		defer cancel()
	}
	resp, err := h.cfg.upstream.Exchange(exchangeCtx, fwd)
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

// buildForwardQuery returns a fresh query carrying the same question and
// recursion-desired bit as the inbound q, with a freshly-randomised ID.
// EDNS is preserved (DO bit, UDPSize, options) so DNSSEC-aware clients
// continue to receive RRSIGs from the upstream.
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
		b = b.EDNS(e)
	}
	m, _ := b.Build()
	return m
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
