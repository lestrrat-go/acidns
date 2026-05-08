package recursive

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// ErrIterationLimit is returned when the resolver fails to reach an
// authoritative answer within the configured iteration cap.
var ErrIterationLimit = errors.New("recursive: iteration limit reached")

// ErrCNAMELoop is returned when a CNAME chain cycles or exceeds the depth
// cap.
var ErrCNAMELoop = errors.New("recursive: CNAME loop or chain too deep")

// ErrAllServersLame is returned when every candidate server returned an
// unusable response (REFUSED, SERVFAIL, or no progress).
var ErrAllServersLame = errors.New("recursive: all candidate servers lame")

// ErrTruncatedAfterTCPFail is returned when a UDP response had TC=1 and
// the TCP fallback failed: the truncated answer is incomplete and must
// not be cached or surfaced as authoritative. A network adversary that
// can drop packets on 53/tcp would otherwise be able to force the
// resolver to operate on partial data — including missing AD bits or
// stripped DNSSEC RRSIGs.
var ErrTruncatedAfterTCPFail = errors.New("recursive: TC=1 with TCP fallback failure")

// Recursive is the public face of the resolver. It implements
// acidns.Handler so it can be plugged into ListenUDP / ListenTCP directly,
// and exposes Resolve for direct use.
type Recursive interface {
	acidns.Handler
	Resolve(ctx context.Context, name wire.Name, t rrtype.Type) (Entry, error)
}

// Validator is the contract recursive expects from a DNSSEC validator.
// Any implementation that satisfies validator.Walker also satisfies this
// interface (acidns/dnssec/validator). The shape is structural so we avoid
// importing the validator package and creating an import cycle through the
// chain walker's Source path.
type Validator interface {
	Resolve(ctx context.Context, name wire.Name, t rrtype.Type) (ValidationResult, error)
}

// ValidationResult is what Validator.Resolve returns. It mirrors the
// validator.Answer shape so any validator package can satisfy it.
type ValidationResult interface {
	Result() ValidationStatus
	Records() []wire.Record
	RCODE() wire.RCODE
	Reason() error
}

// ValidationStatus enumerates the four outcomes of DNSSEC validation. The
// numeric values match validator.Result so the two types interoperate via
// type assertion in any package that imports both.
type ValidationStatus int

const (
	StatusSecure        ValidationStatus = 0
	StatusInsecure      ValidationStatus = 1
	StatusBogus         ValidationStatus = 2
	StatusIndeterminate ValidationStatus = 3
)

// Dialer abstracts how the resolver delivers a query to a chosen server.
type Dialer interface {
	Exchange(ctx context.Context, server netip.AddrPort, q wire.Message) (wire.Message, error)
}

type recursive struct {
	roots         []netip.AddrPort
	cache         Cache
	stats         ServerStats
	maxIterations int
	maxDepth      int
	maxCNAMEs     int
	dialer        Dialer
	validator     Validator
	queryTimeout  time.Duration
	maxNegTTL     time.Duration

	inflightMu sync.Mutex
	inflight   map[string]*inflightCall
}

// inflightCall coalesces concurrent resolveDepth invocations for the
// same (qname, qtype). When N goroutines miss the cache for the same
// key, only one performs the iterative walk; the others wait on done
// and reuse the result. RFC 5452 §6: each independent transmission is
// a fresh spoofing window, so without coalescing a thundering herd
// quadratically multiplies the attacker's chances.
type inflightCall struct {
	done  chan struct{}
	entry Entry
	err   error
}

// New returns a Recursive resolver.
func New(opts ...Option) Recursive {
	c := config{
		maxIterations: 30,
		maxDepth:      8,
		maxCNAMEs:     8,
		queryTimeout:  4 * time.Second,
		maxNegTTL:     time.Hour,
	}
	for _, o := range opts {
		o.applyRecursive(&c)
	}
	if c.cache == nil {
		c.cache = NewMemoryCache()
	}
	if c.stats == nil {
		c.stats = NewMemoryStats()
	}
	if c.dialer == nil {
		c.dialer = defaultDialer{}
	}
	return &recursive{
		roots:         append([]netip.AddrPort(nil), c.roots...),
		cache:         c.cache,
		stats:         c.stats,
		maxIterations: c.maxIterations,
		maxDepth:      c.maxDepth,
		maxCNAMEs:     c.maxCNAMEs,
		dialer:        c.dialer,
		validator:     c.validator,
		queryTimeout:  c.queryTimeout,
		maxNegTTL:     c.maxNegTTL,
		inflight:      make(map[string]*inflightCall),
	}
}

// DefaultDialer returns the built-in Dialer.
func DefaultDialer() Dialer { return defaultDialer{} }

type defaultDialer struct{}

func (defaultDialer) Exchange(ctx context.Context, server netip.AddrPort, q wire.Message) (wire.Message, error) {
	uex, err := acidns.NewUDPExchanger(server)
	if err != nil {
		return nil, err
	}
	resp, err := uex.Exchange(ctx, q)
	if err != nil {
		return nil, err
	}
	if !resp.Flags().Truncated() {
		return resp, nil
	}
	// TC=1 means the response is incomplete. Re-issue over TCP per
	// RFC 7766 §5.2; if the TCP exchange cannot complete, the partial
	// UDP answer is unsafe to cache or surface (DNSSEC RRSIGs may
	// have been the records that didn't fit). Surface an error so the
	// caller can move on to the next candidate server rather than
	// quietly accept a degraded answer.
	tex, terr := acidns.NewTCPExchanger(server)
	if terr != nil {
		return nil, fmt.Errorf("%w: tcp dial: %v", ErrTruncatedAfterTCPFail, terr)
	}
	r2, terr := tex.Exchange(ctx, q)
	if terr != nil {
		return nil, fmt.Errorf("%w: tcp exchange: %v", ErrTruncatedAfterTCPFail, terr)
	}
	return r2, nil
}

// ServeDNS implements acidns.Handler.
func (r *recursive) ServeDNS(ctx context.Context, w acidns.ResponseWriter, q wire.Message) {
	b := wire.NewBuilder().
		ID(q.ID()).
		Response(true).
		RecursionDesired(q.Flags().RecursionDesired()).
		RecursionAvailable(true)

	if len(q.Questions()) == 0 {
		_ = w.WriteMsg(must(b.RCODE(wire.RCODEFormErr).Build()))
		return
	}
	question := q.Questions()[0]
	b = b.Question(question)

	entry, err := r.Resolve(ctx, question.Name(), question.Type())
	if err != nil {
		// DNSSEC bogus: map to SERVFAIL + EDE 6 (DNSSEC Bogus, RFC 8914).
		if errors.Is(err, errBogusAnswer) {
			ede := wire.NewExtendedError(wire.ExtendedErrorDNSSECBogus, "DNSSEC bogus")
			edns := wire.NewEDNSBuilder().UDPSize(1232).Option(ede).Build()
			_ = w.WriteMsg(must(b.RCODE(wire.RCODEServFail).EDNS(edns).Build()))
			return
		}
		_ = w.WriteMsg(must(b.RCODE(wire.RCODEServFail).Build()))
		return
	}
	for _, rec := range entry.Answer {
		b = b.Answer(rec)
	}
	for _, rec := range entry.Authority {
		b = b.Authority(rec)
	}
	for _, rec := range entry.Additional {
		b = b.Additional(rec)
	}
	if entry.RCODE != wire.RCODENoError {
		b = b.RCODE(entry.RCODE)
	}
	if entry.AD {
		b = b.AuthenticData(true)
	}
	_ = w.WriteMsg(must(b.Build()))
}

func must(m wire.Message, err error) wire.Message {
	if err != nil {
		fb, _ := wire.NewBuilder().Response(true).RCODE(wire.RCODEServFail).Build()
		return fb
	}
	return m
}

// errBogusAnswer is the internal sentinel for DNSSEC bogus answers; the
// Handler maps it to SERVFAIL+EDE6.
var errBogusAnswer = errors.New("recursive: dnssec bogus")

// Resolve returns a cached or freshly-iterated entry for (name, t).
func (r *recursive) Resolve(ctx context.Context, name wire.Name, t rrtype.Type) (Entry, error) {
	entry, err := r.resolveDepthFollow(ctx, name, t, 0, 0, nil)
	if err != nil {
		return Entry{}, err
	}
	if r.validator != nil {
		// Run validation on the leaf answer. We do NOT re-validate cache
		// hits separately: the cache stores Entry which carries AD; if AD
		// is set the upstream answer is trustworthy.
		res, err := r.validator.Resolve(ctx, name, t)
		if err != nil {
			return Entry{}, err
		}
		switch res.Result() {
		case StatusBogus:
			return Entry{}, errBogusAnswer
		case StatusSecure:
			entry.AD = true
		}
	}
	return entry, nil
}

// resolveDepthFollow handles CNAME chasing on top of the bare iterative
// resolution in resolveDepth. cnameSeen tracks visited owners to detect
// loops. depth bounds out-of-bailiwick NS recursion, cnameDepth bounds the
// CNAME chain.
func (r *recursive) resolveDepthFollow(ctx context.Context, name wire.Name, t rrtype.Type, depth, cnameDepth int, cnameSeen map[string]struct{}) (Entry, error) {
	if cnameDepth >= r.maxCNAMEs {
		return Entry{}, ErrCNAMELoop
	}
	if cnameSeen == nil {
		cnameSeen = make(map[string]struct{})
	}
	cur := name
	curT := t
	var aggregated Entry
	for {
		if _, seen := cnameSeen[cur.String()]; seen {
			return Entry{}, ErrCNAMELoop
		}
		cnameSeen[cur.String()] = struct{}{}

		entry, err := r.resolveDepth(ctx, cur, curT, depth)
		if err != nil {
			return Entry{}, err
		}
		// Filter each leg's answers to records the leg explicitly asked
		// about — same owner. RFC 5452 §5 + RFC 8499 §6: an
		// authoritative MAY return additional records along the chain,
		// but we don't trust them. A malicious authoritative for
		// `evil.example` returning `evil.example CNAME victim.bank.com`
		// PLUS a forged `victim.bank.com A 1.2.3.4` in the same answer
		// section would otherwise see the forged A flow into the
		// aggregated result. The next leg of the chase re-resolves the
		// CNAME target from roots, getting the legitimate records.
		legAnswers := recordsAt(entry.Answer, cur)
		if len(aggregated.Answer) == 0 && len(aggregated.Authority) == 0 {
			aggregated = entry
			aggregated.Answer = legAnswers
		} else {
			aggregated.Answer = append(aggregated.Answer, legAnswers...)
			if entry.RCODE != wire.RCODENoError {
				aggregated.RCODE = entry.RCODE
			}
			if entry.ExpiresAt.Before(aggregated.ExpiresAt) {
				aggregated.ExpiresAt = entry.ExpiresAt
			}
		}

		// Did we land on a CNAME instead of qtype?
		if curT == rrtype.CNAME {
			return aggregated, nil
		}
		target, ok := pickCNAMETarget(entry.Answer, cur)
		if !ok {
			return aggregated, nil
		}
		// Did we already see qtype answers at the previous owner? If yes,
		// we're done.
		if hasTypeAt(entry.Answer, cur, curT) {
			return aggregated, nil
		}
		cnameDepth++
		if cnameDepth >= r.maxCNAMEs {
			return Entry{}, ErrCNAMELoop
		}
		cur = target
	}
}

// recordsAt returns the subset of records whose owner equals name. Used
// during CNAME chasing to discard "extra" records an authoritative
// server may have bundled alongside the requested data — the resolver
// re-resolves the chase target from roots, so trusting the bundled
// records would let one zone forge data for another.
func recordsAt(records []wire.Record, name wire.Name) []wire.Record {
	out := make([]wire.Record, 0, len(records))
	for _, r := range records {
		if r.Name().Equal(name) {
			out = append(out, r)
		}
	}
	return out
}

func (r *recursive) resolveDepth(ctx context.Context, name wire.Name, t rrtype.Type, depth int) (Entry, error) {
	if depth >= r.maxDepth {
		return Entry{}, fmt.Errorf("recursive: depth limit reached for %s", name)
	}
	if e, ok := r.cache.Get(name, t); ok {
		return e, nil
	}

	// Singleflight: coalesce concurrent misses for the same key.
	key := nameKey(name) + "\x00" + fmt.Sprintf("%d", t)
	r.inflightMu.Lock()
	if call, ok := r.inflight[key]; ok {
		r.inflightMu.Unlock()
		select {
		case <-call.done:
			return call.entry, call.err
		case <-ctx.Done():
			return Entry{}, ctx.Err()
		}
	}
	call := &inflightCall{done: make(chan struct{})}
	r.inflight[key] = call
	r.inflightMu.Unlock()
	defer func() {
		r.inflightMu.Lock()
		delete(r.inflight, key)
		r.inflightMu.Unlock()
		close(call.done)
	}()

	entry, err := r.resolveDepthInner(ctx, name, t, depth)
	call.entry = entry
	call.err = err
	return entry, err
}

func (r *recursive) resolveDepthInner(ctx context.Context, name wire.Name, t rrtype.Type, depth int) (Entry, error) {
	servers := append([]netip.AddrPort(nil), r.roots...)
	for range r.maxIterations {
		if len(servers) == 0 {
			return Entry{}, fmt.Errorf("recursive: no servers to query for %s", name)
		}
		ranked := rankServers(r.stats, servers)
		resp, used, err := r.queryAny(ctx, ranked, name, t)
		if err != nil {
			return Entry{}, fmt.Errorf("recursive: query failed: %w", err)
		}
		// Lame check: REFUSED or SERVFAIL → mark and try next server set.
		rcode := resp.Flags().RCODE()
		if rcode == wire.RCODERefused || rcode == wire.RCODEServFail {
			r.stats.Record(used, 0, false)
			// Drop the lame server and retry remaining without re-querying
			// the failed one — but if we've exhausted the set, give up.
			servers = removeServer(ranked, used)
			if len(servers) == 0 {
				return Entry{}, ErrAllServersLame
			}
			continue
		}

		// Authoritative answer or NXDOMAIN is terminal.
		if resp.Flags().Authoritative() {
			entry := r.entryFromResponse(name, resp)
			r.cache.Put(name, t, entry)
			return entry, nil
		}
		// Some servers don't set AA but still answer; if there are matching
		// records in the answer section, treat it as terminal.
		if hasAnswerFor(resp, name, t) {
			entry := r.entryFromResponse(name, resp)
			r.cache.Put(name, t, entry)
			return entry, nil
		}

		// Otherwise treat it as a referral.
		next := r.serversFromReferral(ctx, resp, depth)
		if len(next) == 0 {
			return Entry{}, fmt.Errorf("recursive: empty referral for %s", name)
		}
		servers = next
	}
	return Entry{}, ErrIterationLimit
}

// queryAny tries servers in order, recording RTT/failure for each. Returns
// the response and the server that produced it. A fresh transaction ID is
// generated for every transmission so a late datagram from a slow server
// can't be confused with the next server's reply (RFC 5452 §5).
func (r *recursive) queryAny(ctx context.Context, servers []netip.AddrPort, name wire.Name, t rrtype.Type) (wire.Message, netip.AddrPort, error) {
	var lastErr error
	for _, s := range servers {
		id, err := randomID()
		if err != nil {
			return nil, netip.AddrPort{}, err
		}
		q, err := wire.NewBuilder().
			ID(id).
			Question(wire.NewQuestion(name, t)).
			EDNS(wire.NewEDNSBuilder().UDPSize(1232).Build()).
			Build()
		if err != nil {
			return nil, netip.AddrPort{}, err
		}

		exchCtx := ctx
		var cancel context.CancelFunc
		if r.queryTimeout > 0 {
			exchCtx, cancel = context.WithTimeout(ctx, r.queryTimeout)
		}
		started := time.Now()
		resp, err := r.dialer.Exchange(exchCtx, s, q)
		if cancel != nil {
			cancel()
		}
		rtt := time.Since(started)
		if err == nil {
			r.stats.Record(s, rtt, true)
			return resp, s, nil
		}
		r.stats.Record(s, rtt, false)
		lastErr = err
		if ctx.Err() != nil {
			return nil, netip.AddrPort{}, ctx.Err()
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no servers")
	}
	return nil, netip.AddrPort{}, lastErr
}

// serversFromReferral picks the addresses to query next. It prefers
// in-bailiwick glue from the additional section and falls back to
// recursively resolving the NS targets for out-of-bailiwick delegations.
//
// Glue is only trusted when both the NS target and the glue's owner are
// at-or-below the delegating zone (the owner of the NS RRset). RFC 5452
// §5.4.1 — accepting out-of-bailiwick glue lets a malicious nameserver
// poison arbitrary names by stuffing the additional section with A
// records for unrelated owners.
func (r *recursive) serversFromReferral(ctx context.Context, resp wire.Message, depth int) []netip.AddrPort {
	zone := referralZone(resp)
	var glued []netip.AddrPort
	var ungluedNS []wire.Name
	for _, auth := range resp.Authorities() {
		if auth.Type() != rrtype.NS {
			continue
		}
		// All NS records in a referral must share the same owner (the
		// delegating zone). A different owner is anomalous; skip it.
		if zone.IsValid() && !auth.Name().Equal(zone) {
			continue
		}
		ns, ok := wire.RDataAs[rdata.NS](auth)
		if !ok {
			continue
		}
		target := ns.NSDName()
		if zone.IsValid() && inBailiwick(zone, target) {
			if addrs := glueFor(target, resp.Additionals(), zone); len(addrs) > 0 {
				glued = append(glued, addrs...)
				continue
			}
		}
		ungluedNS = append(ungluedNS, target)
	}
	if len(glued) > 0 {
		return glued
	}
	var out []netip.AddrPort
	for _, ns := range ungluedNS {
		entry, err := r.resolveDepth(ctx, ns, rrtype.A, depth+1)
		if err != nil {
			continue
		}
		for _, rec := range entry.Answer {
			if rec.Type() == rrtype.A {
				a, ok := wire.RDataAs[rdata.A](rec)
				if !ok {
					continue
				}
				out = append(out, netip.AddrPortFrom(a.Addr(), 53))
			}
		}
	}
	return out
}

// referralZone returns the owner name of the NS RRset in resp's
// authority section — i.e., the zone that owns the delegation. If no NS
// is present (the referral is malformed), an invalid Name is returned
// and the caller falls back to out-of-bailiwick recursion.
func referralZone(resp wire.Message) wire.Name {
	for _, auth := range resp.Authorities() {
		if auth.Type() == rrtype.NS {
			return auth.Name()
		}
	}
	return wire.Name{}
}

// inBailiwick reports whether descendant is at-or-below ancestor.
func inBailiwick(ancestor, descendant wire.Name) bool {
	cur := descendant
	for cur.IsValid() {
		if cur.Equal(ancestor) {
			return true
		}
		p, ok := cur.Parent()
		if !ok || cur.Equal(p) {
			return false
		}
		cur = p
	}
	return false
}

// glueFor extracts in-bailiwick A/AAAA glue records for target from the
// additional section. zone is the delegating zone — glue records owned
// by a name outside the zone are not trustworthy and are skipped.
func glueFor(target wire.Name, additional []wire.Record, zone wire.Name) []netip.AddrPort {
	var out []netip.AddrPort
	for _, add := range additional {
		if !add.Name().Equal(target) {
			continue
		}
		if zone.IsValid() && !inBailiwick(zone, add.Name()) {
			continue
		}
		switch add.Type() {
		case rrtype.A:
			a, ok := wire.RDataAs[rdata.A](add)
			if !ok {
				continue
			}
			out = append(out, netip.AddrPortFrom(a.Addr(), 53))
		case rrtype.AAAA:
			aaaa, ok := wire.RDataAs[rdata.AAAA](add)
			if !ok {
				continue
			}
			out = append(out, netip.AddrPortFrom(aaaa.Addr(), 53))
		}
	}
	return out
}

func hasAnswerFor(resp wire.Message, name wire.Name, t rrtype.Type) bool {
	for _, rec := range resp.Answers() {
		if rec.Type() == t && rec.Name().Equal(name) {
			return true
		}
		if rec.Type() == rrtype.CNAME && rec.Name().Equal(name) {
			return true
		}
	}
	return false
}

// pickCNAMETarget returns the CNAME target if records contains a CNAME at
// owner.
func pickCNAMETarget(records []wire.Record, owner wire.Name) (wire.Name, bool) {
	for _, r := range records {
		if r.Type() != rrtype.CNAME {
			continue
		}
		if !r.Name().Equal(owner) {
			continue
		}
		c, ok := wire.RDataAs[rdata.CNAME](r)
		if !ok {
			continue
		}
		return c.Target(), true
	}
	return wire.Name{}, false
}

func hasTypeAt(records []wire.Record, owner wire.Name, t rrtype.Type) bool {
	for _, r := range records {
		if r.Type() == t && r.Name().Equal(owner) {
			return true
		}
	}
	return false
}

// removeServer returns a copy of servers with target removed.
func removeServer(servers []netip.AddrPort, target netip.AddrPort) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(servers))
	for _, s := range servers {
		if s == target {
			continue
		}
		out = append(out, s)
	}
	return out
}

func (r *recursive) entryFromResponse(qname wire.Name, resp wire.Message) Entry {
	ttl := minTTL(60*time.Second, resp.Answers(), resp.Authorities())
	if len(resp.Answers()) == 0 {
		if neg := negativeCacheTTL(resp.Authorities()); neg > 0 && neg < ttl {
			ttl = neg
		}
		// RFC 2308 §4 caps negative caching at 24 hours; we apply
		// the configured (smaller-by-default) limit here so a
		// hostile zone with a multi-year SOA MINIMUM cannot pin
		// NXDOMAIN/NoData entries.
		if r.maxNegTTL > 0 && ttl > r.maxNegTTL {
			ttl = r.maxNegTTL
		}
	}
	answers, authority, additional := bailiwickFilter(qname, resp)
	return Entry{
		Answer:     answers,
		Authority:  authority,
		Additional: additional,
		RCODE:      resp.Flags().RCODE(),
		AA:         resp.Flags().Authoritative(),
		AD:         resp.Flags().AuthenticData(),
		ExpiresAt:  time.Now().Add(ttl),
	}
}

// bailiwickFilter sanitises a terminal response before it is cached or
// returned to the caller. It enforces RFC 5452 §6: a malicious upstream
// must not be able to insert records for unrelated owners by stuffing the
// answer/authority/additional sections of a response to qname.
//
//   - Answer: keep records whose owner is qname or a CNAME target reachable
//     from qname through the answer's own chain. Out-of-chain records (the
//     "Kashpureff" injection) are dropped.
//   - Authority: keep records whose owner is at-or-above qname (zone-level
//     SOA/NS), since those are the only authority records relevant to a
//     terminal answer for qname.
//   - Additional: keep OPT and records whose owner is referenced by a kept
//     Answer-section CNAME target or Authority-section NS rdata, and whose
//     owner is at-or-below the deepest ancestor we kept in Authority (the
//     closest enclosing zone). Everything else — and in particular A/AAAA
//     records for unrelated names — is discarded.
func bailiwickFilter(qname wire.Name, resp wire.Message) (answers, authority, additional []wire.Record) {
	chain := map[string]struct{}{nameKey(qname): {}}
	for {
		grew := false
		for _, r := range resp.Answers() {
			if r.Type() != rrtype.CNAME {
				continue
			}
			if _, ok := chain[nameKey(r.Name())]; !ok {
				continue
			}
			c, ok := wire.RDataAs[rdata.CNAME](r)
			if !ok {
				continue
			}
			tk := nameKey(c.Target())
			if _, exists := chain[tk]; exists {
				continue
			}
			chain[tk] = struct{}{}
			grew = true
		}
		if !grew {
			break
		}
	}

	answers = make([]wire.Record, 0, len(resp.Answers()))
	for _, r := range resp.Answers() {
		if _, ok := chain[nameKey(r.Name())]; ok {
			answers = append(answers, r)
		}
	}

	authority = make([]wire.Record, 0, len(resp.Authorities()))
	for _, r := range resp.Authorities() {
		if inBailiwick(r.Name(), qname) {
			authority = append(authority, r)
		}
	}

	zoneCut := deepestAncestor(authority, qname)

	referenced := map[string]struct{}{}
	for _, r := range answers {
		if c, ok := wire.RDataAs[rdata.CNAME](r); ok {
			referenced[nameKey(c.Target())] = struct{}{}
		}
	}
	for _, r := range authority {
		if ns, ok := wire.RDataAs[rdata.NS](r); ok {
			referenced[nameKey(ns.NSDName())] = struct{}{}
		}
	}

	additional = make([]wire.Record, 0, len(resp.Additionals()))
	for _, r := range resp.Additionals() {
		if r.Type() == rrtype.OPT {
			additional = append(additional, r)
			continue
		}
		if _, ok := referenced[nameKey(r.Name())]; !ok {
			continue
		}
		if zoneCut.IsValid() && !inBailiwick(zoneCut, r.Name()) {
			continue
		}
		additional = append(additional, r)
	}
	return answers, authority, additional
}

// deepestAncestor returns the deepest owner among authority records that
// is at-or-above qname; this is the closest enclosing zone the response
// claims authority over and bounds what owners we will accept in the
// additional section.
func deepestAncestor(authority []wire.Record, qname wire.Name) wire.Name {
	var best wire.Name
	for _, r := range authority {
		if !inBailiwick(r.Name(), qname) {
			continue
		}
		if !best.IsValid() || r.Name().WireLen() > best.WireLen() {
			best = r.Name()
		}
	}
	return best
}

func nameKey(n wire.Name) string {
	return string(n.AppendWire(nil))
}

// negativeCacheTTL implements RFC 2308 §5.
func negativeCacheTTL(authority []wire.Record) time.Duration {
	for _, r := range authority {
		if r.Type() != rrtype.SOA {
			continue
		}
		soa, ok := wire.RDataAs[rdata.SOA](r)
		if !ok {
			continue
		}
		minTTL := soa.Minimum()
		if r.TTL() < minTTL {
			return r.TTL()
		}
		return minTTL
	}
	return 0
}

func randomID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}
