package mdns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
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
// service instance. The minimal set is host A/AAAA + an SRV+TXT under the
// service type, with PTR pointing the type at the instance.
//
// Names are rendered in mDNS form (".local." suffix) by the Announcer if
// they are unqualified.
type Publication struct {
	// Instance: e.g. "Living Room TV._http._tcp.local."
	Instance wire.Name
	// Type: e.g. "_http._tcp.local."
	Type wire.Name
	// Host: e.g. "tv-living-room.local."
	Host wire.Name
	// Port the service listens on.
	Port uint16
	// IPv4/IPv6 addresses of Host.
	Addrs []netip.Addr
	// TXT key/value pairs.
	Text map[string]string
	// TTL applied to all published records (RFC 6762 recommends 120s for
	// non-host A/AAAA and 4500s for "all other" records). Defaults to 120s.
	TTL time.Duration
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
		o.applyAnnouncer(&c)
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
	if p.TTL == 0 {
		p.TTL = 120 * time.Second
	}
	if !p.Instance.IsValid() || !p.Type.IsValid() || !p.Host.IsValid() {
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
// (true, nil) if any record names ours with conflicting rdata.
func (a *announcer) listenForConflict(ctx context.Context, p Publication) (bool, error) {
	for {
		msg, err := a.cfg.transport.Recv(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return false, nil //nolint:nilerr // ctx expiry means "no conflict observed within window"
			}
			return false, err
		}
		// Inspect ANSWER section. We treat any record that names our
		// instance/host with rdata DIFFERENT from ours as a conflict.
		if conflictsWith(msg.Answers(), p) {
			return true, nil
		}
	}
}

// conflictsWith inspects records for any that name our publication's
// owners (Instance, Host) but advertise rdata different from ours.
func conflictsWith(records []wire.Record, p Publication) bool {
	for _, r := range records {
		switch r.Type() {
		case rrtype.SRV:
			if !r.Name().Equal(p.Instance) {
				continue
			}
			s, ok := wire.RDataAs[rdata.SRV](r)
			if !ok {
				continue
			}
			if !s.Target().Equal(p.Host) || s.Port() != p.Port {
				return true
			}
		case rrtype.A:
			if !r.Name().Equal(p.Host) {
				continue
			}
			a, ok := wire.RDataAs[rdata.A](r)
			if !ok {
				continue
			}
			if !addrsContain(p.Addrs, a.Addr()) {
				return true
			}
		case rrtype.AAAA:
			if !r.Name().Equal(p.Host) {
				continue
			}
			aaaa, ok := wire.RDataAs[rdata.AAAA](r)
			if !ok {
				continue
			}
			if !addrsContain(p.Addrs, aaaa.Addr()) {
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
	b := wire.NewBuilder().
		ID(0).
		Question(wire.NewQuestionClass(p.Instance, rrtype.ANY, rrtype.ClassIN)).
		Question(wire.NewQuestionClass(p.Host, rrtype.ANY, rrtype.ClassIN))
	for _, r := range publicationRecords(p, false /*flushBit*/) {
		b = b.Authority(r)
	}
	return b.Build()
}

// buildAnnouncement builds an unsolicited response (RFC 6762 §8.3) with
// the cache-flush bit set on every owned record.
func buildAnnouncement(p Publication) (wire.Message, error) {
	b := wire.NewBuilder().
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
	zero.TTL = 0
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
	// SRV at instance.
	out = append(out, wire.NewRecordClass(p.Instance, cls, p.TTL,
		rdata.NewSRV(0, 0, p.Port, p.Host)))
	// TXT at instance (single TXT with all key=value strings).
	if len(p.Text) > 0 {
		strs := make([]string, 0, len(p.Text))
		for k, v := range p.Text {
			strs = append(strs, k+"="+v)
		}
		txt, err := rdata.NewTXT(strs...)
		if err == nil {
			out = append(out, wire.NewRecordClass(p.Instance, cls, p.TTL, txt))
		}
	}
	// PTR at type → instance (cache-flush bit NOT set on PTR; PTR is a
	// shared-set record per RFC 6762 §10.2).
	out = append(out, wire.NewRecord(p.Type, p.TTL,
		rdata.NewPTR(p.Instance)))
	// A/AAAA at host.
	for _, a := range p.Addrs {
		if a.Is4() {
			out = append(out, wire.NewRecordClass(p.Host, cls, p.TTL, rdata.NewA(a)))
		}
		if a.Is6() {
			out = append(out, wire.NewRecordClass(p.Host, cls, p.TTL, rdata.NewAAAA(a)))
		}
	}
	return out
}
