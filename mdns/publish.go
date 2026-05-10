package mdns

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/option/v3"
)

// CacheFlushBit is the high bit of the CLASS field (RFC 6762 §10.2). When
// set on a record in a response, receivers must flush prior cached records
// with the same name+type+class except for the one in the response.
const CacheFlushBit uint16 = 0x8000

// ErrConflict is returned when a probe receives an authoritative answer
// claiming the same names/records — meaning another responder already
// owns the identity (RFC 6762 §8.1).
var ErrConflict = errors.New("mdns: probe detected conflict")

// Publication describes the records an Announcer will publish for a
// service instance. The minimal set is host A/AAAA + an SRV+TXT under
// the service type, with PTR pointing the type at the instance.
//
// Construct via [NewPublicationBuilder]; the fields are unexported so
// a Publication cannot be mutated mid-Announce, where a mutation
// would break the cache-flush invariants the announcer maintains.
type Publication struct {
	instance wire.Name         // e.g. "Living Room TV._http._tcp.local."
	typ      wire.Name         // e.g. "_http._tcp.local."
	host     wire.Name         // e.g. "tv-living-room.local."
	port     uint16            // service port
	addrs    []netip.Addr      // IPv4/IPv6 addresses of host
	text     map[string]string // TXT key/value pairs
	ttl      time.Duration     // record TTL
}

// PublicationBuilder accumulates the components of a [Publication]
// and validates them in [PublicationBuilder.Build].
type PublicationBuilder struct {
	p   Publication
	err error
}

// NewPublicationBuilder returns a fresh builder. Required: Instance,
// Type, Host. Optional: Port, Addr (one or more), TXT (one or more
// pairs), TTL (defaults to 120s per RFC 6762).
func NewPublicationBuilder() *PublicationBuilder { return &PublicationBuilder{} }

// Instance sets the per-instance name (e.g. "Living Room TV._http._tcp.local.").
func (b *PublicationBuilder) Instance(n wire.Name) *PublicationBuilder {
	b.p.instance = n
	return b
}

// Type sets the service-type name (e.g. "_http._tcp.local.").
func (b *PublicationBuilder) Type(n wire.Name) *PublicationBuilder {
	b.p.typ = n
	return b
}

// Host sets the host name (e.g. "tv-living-room.local.").
func (b *PublicationBuilder) Host(n wire.Name) *PublicationBuilder {
	b.p.host = n
	return b
}

// Port sets the port the service listens on.
func (b *PublicationBuilder) Port(p uint16) *PublicationBuilder {
	b.p.port = p
	return b
}

// Addr appends an IPv4 or IPv6 address for the host.
func (b *PublicationBuilder) Addr(a netip.Addr) *PublicationBuilder {
	b.p.addrs = append(b.p.addrs, a)
	return b
}

// Addrs appends multiple addresses in one call.
func (b *PublicationBuilder) Addrs(a ...netip.Addr) *PublicationBuilder {
	b.p.addrs = append(b.p.addrs, a...)
	return b
}

// Text appends a single TXT key/value pair.
func (b *PublicationBuilder) Text(key, value string) *PublicationBuilder {
	if b.p.text == nil {
		b.p.text = make(map[string]string)
	}
	b.p.text[key] = value
	return b
}

// TextMap merges every entry of m into the publication's TXT pairs.
func (b *PublicationBuilder) TextMap(m map[string]string) *PublicationBuilder {
	if len(m) == 0 {
		return b
	}
	if b.p.text == nil {
		b.p.text = make(map[string]string, len(m))
	}
	for k, v := range m {
		b.p.text[k] = v
	}
	return b
}

// TTL sets the TTL applied to every published record. Defaults to
// 120 seconds when unset.
func (b *PublicationBuilder) TTL(d time.Duration) *PublicationBuilder {
	b.p.ttl = d
	return b
}

// Build validates the accumulated fields and returns the immutable
// [Publication]. Returns an error when Instance, Type, or Host is
// missing. Slices and maps are copied so a later mutation of the
// caller's source does not leak into the published record.
// Build returns the assembled Publication and resets b to the zero
// state — single-shot semantics. The Publication's slice/map fields
// ALIAS the values the builder accumulated; the reset zeroes b's
// fields so subsequent reuse cannot mutate the previously-built
// Publication.
func (b *PublicationBuilder) Build() (Publication, error) {
	if b.err != nil {
		err := b.err
		*b = PublicationBuilder{}
		return Publication{}, err
	}
	if !b.p.instance.IsValid() || !b.p.typ.IsValid() || !b.p.host.IsValid() {
		*b = PublicationBuilder{}
		return Publication{}, fmt.Errorf("mdns: incomplete publication (Instance/Type/Host required)")
	}
	out := b.p
	if out.ttl == 0 {
		out.ttl = 120 * time.Second
	}
	*b = PublicationBuilder{}
	return out, nil
}

// Transport is the network the Announcer sends and receives on. The
// concrete implementation lives in the package's network code; tests pass
// a fake.
type Transport interface {
	Send(msg wire.Message) error
	Recv(ctx context.Context) (wire.Message, error)
}

// Announcer drives the probe/announce/goodbye lifecycle of an mDNS
// publication.
type Announcer interface {
	// Announce probes for conflicts, then announces the publication.
	// Returns ErrConflict if another responder owns any of the names.
	Announce(ctx context.Context, p Publication) error
	// Withdraw sends goodbye packets (TTL=0) for the previously
	// announced records and clears state.
	Withdraw(ctx context.Context) error
}

// NewAnnouncer constructs an Announcer.
func NewAnnouncer(opts ...AnnouncerOption) (Announcer, error) {
	c := announcerConfig{
		probeWait:     250 * time.Millisecond,
		probeCount:    3,
		announceWait:  1 * time.Second,
		announceCount: 2,
		now:           time.Now,
	}
	for _, o := range opts {
		switch o.Ident() {
		case identAnnouncerTransport{}:
			c.transport = option.MustGet[Transport](o)
		case identProbeTiming{}:
			t := option.MustGet[timing](o)
			c.probeWait = t.wait
			c.probeCount = t.count
		case identAnnounceTiming{}:
			t := option.MustGet[timing](o)
			c.announceWait = t.wait
			c.announceCount = t.count
		case identAnnouncerClock{}:
			c.now = option.MustGet[func() time.Time](o)
		}
	}
	if c.transport == nil {
		return nil, fmt.Errorf("mdns: NewAnnouncer requires a Transport")
	}
	return &announcer{cfg: c}, nil
}

type announcer struct {
	cfg announcerConfig

	mu      sync.Mutex
	current *Publication
}

func (a *announcer) Announce(ctx context.Context, p Publication) error {
	if p.ttl == 0 {
		p.ttl = 120 * time.Second
	}
	if !p.instance.IsValid() || !p.typ.IsValid() || !p.host.IsValid() {
		return fmt.Errorf("mdns: incomplete publication (Instance/Type/Host required)")
	}

	// Probe phase (RFC 6762 §8.1): send `probeCount` queries spaced
	// `probeWait` apart, listen for any matching response from another
	// responder. Any response that carries our names with conflicting
	// rdata aborts as ErrConflict.
	probe, err := buildProbe(p)
	if err != nil {
		return fmt.Errorf("mdns: build probe: %w", err)
	}
	for range a.cfg.probeCount {
		if err := a.cfg.transport.Send(probe); err != nil {
			return fmt.Errorf("mdns: send probe: %w", err)
		}
		// Listen until next probe deadline.
		listenCtx, cancel := context.WithTimeout(ctx, a.cfg.probeWait)
		conflict, err := a.listenForConflict(listenCtx, p)
		cancel()
		if err != nil {
			return err
		}
		if conflict {
			return ErrConflict
		}
	}

	// Announce phase (RFC 6762 §8.3).
	ann, err := buildAnnouncement(p)
	if err != nil {
		return fmt.Errorf("mdns: build announcement: %w", err)
	}
	for i := range a.cfg.announceCount {
		if err := a.cfg.transport.Send(ann); err != nil {
			return fmt.Errorf("mdns: send announcement: %w", err)
		}
		if i+1 < a.cfg.announceCount {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(a.cfg.announceWait):
			}
		}
	}

	a.mu.Lock()
	cp := p
	a.current = &cp
	a.mu.Unlock()
	return nil
}

func (a *announcer) Withdraw(ctx context.Context) error {
	a.mu.Lock()
	cur := a.current
	a.current = nil
	a.mu.Unlock()
	if cur == nil {
		return nil
	}
	bye, err := buildGoodbye(*cur)
	if err != nil {
		return fmt.Errorf("mdns: build goodbye: %w", err)
	}
	if err := a.cfg.transport.Send(bye); err != nil {
		return fmt.Errorf("mdns: send goodbye: %w", err)
	}
	_ = ctx
	return nil
}

// listenForConflict drains transport.Recv until ctx expires, returning
// (true, nil) if a conflict resolves with us as the loser.
//
// Two paths:
//
//   - ANSWER section: a record from someone's existing announcement
//     names ours with conflicting rdata. RFC 6762 §9 says we MUST
//     defer; abort with ErrConflict.
//   - AUTHORITY section: a probe from a simultaneous announcer with
//     conflicting proposed records. RFC 6762 §8.2 calls for a
//     lexicographic tiebreak — only the loser of the compare aborts.
func (a *announcer) listenForConflict(ctx context.Context, p Publication) (bool, error) {
	for {
		msg, err := a.cfg.transport.Recv(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return false, nil //nolint:nilerr // ctx expiry means "no conflict observed within window"
			}
			return false, err
		}
		if conflictsWith(msg.Answers(), p) {
			return true, nil
		}
		theirs := pertinentRecords(msg.Authorities(), p)
		if len(theirs) == 0 {
			continue
		}
		ours := pertinentRecords(publicationRecords(p, false), p)
		if !setsAreEquivalent(theirs, ours) && proberWinsTiebreak(theirs, ours) {
			return true, nil
		}
		// We win or tie — ignore the probe and keep listening.
	}
}

// pertinentRecords filters to records owned by our instance/host (the
// "complete record set" RFC 6762 §8.2 calls out for the tiebreak).
// Includes SRV/TXT at the instance and A/AAAA at the host; PTR records
// are shared-set per RFC 6762 §10.2 and don't participate.
func pertinentRecords(records []wire.Record, p Publication) []wire.Record {
	var out []wire.Record
	for _, r := range records {
		if r.Name().Equal(p.instance) || r.Name().Equal(p.host) {
			out = append(out, r)
		}
	}
	return out
}

// setsAreEquivalent reports whether ours and theirs have the same
// canonical record content. Equivalent sets imply both probers are
// proposing identical records — there is no conflict, just two
// honestly-uncoordinated copies, and the announce phase's cache-flush
// bit will reconcile them at the consumer.
func setsAreEquivalent(a, b []wire.Record) bool {
	if len(a) != len(b) {
		return false
	}
	abs := canonicalSetBytes(a)
	bbs := canonicalSetBytes(b)
	return bytes.Equal(abs, bbs)
}

// proberWinsTiebreak runs the RFC 6762 §8.2 lexicographic compare.
// Returns true when 'theirs' (the incoming probe's records) sorts
// lexicographically later than ours — meaning they win, and we must
// defer.
func proberWinsTiebreak(theirs, ours []wire.Record) bool {
	tBytes := canonicalSetBytes(theirs)
	oBytes := canonicalSetBytes(ours)
	return bytes.Compare(tBytes, oBytes) > 0
}

// canonicalSetBytes produces a deterministic bytewise representation
// of a record set for §8.2 tiebreak comparison: each record encoded
// as class(2) || type(2) || canonical-rdata, sorted ascending, then
// concatenated. Owner names are excluded from the per-record bytes
// because both parties' records share the conflicting owner; the
// compare hinges on rdata + class + type.
func canonicalSetBytes(records []wire.Record) []byte {
	if len(records) == 0 {
		return nil
	}
	parts := make([][]byte, 0, len(records))
	for _, r := range records {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint16(buf[0:], uint16(r.Class())&0x7fff)
		binary.BigEndian.PutUint16(buf[2:], uint16(r.Type()))
		buf = append(buf, rdata.Pack(r.RData())...)
		parts = append(parts, buf)
	}
	sort.Slice(parts, func(i, j int) bool { return bytes.Compare(parts[i], parts[j]) < 0 })
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// conflictsWith inspects records for any that name our publication's
// owners (Instance, Host) but advertise rdata different from ours.
func conflictsWith(records []wire.Record, p Publication) bool {
	for _, r := range records {
		switch r.Type() {
		case rrtype.SRV:
			if !r.Name().Equal(p.instance) {
				continue
			}
			s, ok := wire.RDataAs[rdata.SRV](r)
			if !ok {
				continue
			}
			if !s.Target().Equal(p.host) || s.Port() != p.port {
				return true
			}
		case rrtype.A:
			if !r.Name().Equal(p.host) {
				continue
			}
			a, ok := wire.RDataAs[rdata.A](r)
			if !ok {
				continue
			}
			if !addrsContain(p.addrs, a.Addr()) {
				return true
			}
		case rrtype.AAAA:
			if !r.Name().Equal(p.host) {
				continue
			}
			aaaa, ok := wire.RDataAs[rdata.AAAA](r)
			if !ok {
				continue
			}
			if !addrsContain(p.addrs, aaaa.Addr()) {
				return true
			}
		}
	}
	return false
}

func addrsContain(haystack []netip.Addr, needle netip.Addr) bool {
	return slices.Contains(haystack, needle)
}

// buildProbe builds the QU=1 probe message (RFC 6762 §8.1). It places our
// proposed records in the AUTHORITY section so other responders can
// detect conflicts during tie-breaking.
func buildProbe(p Publication) (wire.Message, error) {
	b := wire.NewMessageBuilder().
		ID(0).
		Question(wire.NewQuestionClass(p.instance, rrtype.ANY, rrtype.ClassIN)).
		Question(wire.NewQuestionClass(p.host, rrtype.ANY, rrtype.ClassIN))
	for _, r := range publicationRecords(p, false /*flushBit*/) {
		b = b.Authority(r)
	}
	return b.Build()
}

// buildAnnouncement builds an unsolicited response (RFC 6762 §8.3) with
// the cache-flush bit set on every owned record.
func buildAnnouncement(p Publication) (wire.Message, error) {
	b := wire.NewMessageBuilder().
		ID(0).
		Response(true).
		Authoritative(true)
	for _, r := range publicationRecords(p, true) {
		b = b.Answer(r)
	}
	return b.Build()
}

// buildGoodbye is an announcement variant with TTL=0 (§10.1).
func buildGoodbye(p Publication) (wire.Message, error) {
	zero := p
	zero.ttl = 0
	return buildAnnouncement(zero)
}

// publicationRecords returns the SRV, TXT, host A/AAAA, and PTR records
// that constitute p. flushBit toggles the cache-flush bit (high bit of
// CLASS) on each owned record.
func publicationRecords(p Publication, flushBit bool) []wire.Record {
	cls := rrtype.ClassIN
	if flushBit {
		cls = rrtype.Class(uint16(rrtype.ClassIN) | CacheFlushBit)
	}
	var out []wire.Record
	// SRV at instance. Publication.Validate enforces non-zero host;
	// NewSRV cannot fail here in practice but surface the error so a
	// future change that loosens the validate gate fails fast.
	srv, err := rdata.NewSRV(0, 0, p.port, p.host)
	if err != nil {
		return nil
	}
	out = append(out, wire.NewRecordClass(p.instance, cls, p.ttl, srv))
	// TXT at instance (single TXT with all key=value strings).
	if len(p.text) > 0 {
		strs := make([]string, 0, len(p.text))
		for k, v := range p.text {
			strs = append(strs, k+"="+v)
		}
		txt, err := rdata.NewTXT(strs...)
		if err == nil {
			out = append(out, wire.NewRecordClass(p.instance, cls, p.ttl, txt))
		}
	}
	// PTR at type → instance (cache-flush bit NOT set on PTR; PTR is a
	// shared-set record per RFC 6762 §10.2).
	out = append(out, wire.NewRecord(p.typ, p.ttl,
		rdata.MustNewPTR(p.instance)))
	// A/AAAA at host.
	for _, a := range p.addrs {
		if a.Is4() {
			out = append(out, wire.NewRecordClass(p.host, cls, p.ttl, rdata.MustNewA(a)))
		}
		if a.Is6() {
			out = append(out, wire.NewRecordClass(p.host, cls, p.ttl, rdata.MustNewAAAA(a)))
		}
	}
	return out
}
