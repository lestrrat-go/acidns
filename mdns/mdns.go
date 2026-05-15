// Package mdns implements multicast DNS (RFC 6762) and the subset of
// DNS-Service Discovery (RFC 6763) used to browse and resolve services
// on the local link.
//
// The package is intentionally minimal — Browse and Resolve cover the
// service-discovery use cases; service announcement (Publish) is out of
// scope for this version. The msg format reuses dnsmsg, so unit tests
// for query/response synthesis run without any network at all.
package mdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/option/v3"
	"golang.org/x/net/ipv4"
)

// Default mDNS link-local addresses (RFC 6762 §3).
const (
	Port    = 5353
	GroupV4 = "224.0.0.251"
	GroupV6 = "ff02::fb"
)

// localDomainName is the special-use suffix that mDNS responders own.
// Computed once at package init so callers cannot reassign the global
// and subtly redirect every subsequent lookup.
var localDomainName = wire.MustParseName("local")

// LocalDomain returns the mDNS-owned ".local" suffix as a fresh
// [wire.Name] value. The previous shape exposed a package-level var
// that any caller could reassign; the function form is non-mutable
// by construction.
func LocalDomain() wire.Name { return localDomainName }

// ErrNoResponse is returned when Browse or Resolve produces no answers
// within the configured deadline.
var ErrNoResponse = errors.New("mdns: no responses received")

// Service is a single discovered instance.
type Service struct {
	instance string
	typ      wire.Name
	host     wire.Name
	port     uint16
	priority uint16
	weight   uint16
	addrs    []netip.Addr
	text     map[string]string
	ttl      time.Duration
}

// Instance returns the instance name (the "Foo Bar" part of
// "Foo Bar._http._tcp.local.").
func (s Service) Instance() string { return s.instance }

// Type returns the service type ("_http._tcp.local.").
func (s Service) Type() wire.Name { return s.typ }

// Host returns the target host name.
func (s Service) Host() wire.Name { return s.host }

// Port returns the service port.
func (s Service) Port() uint16 { return s.port }

// Priority returns the service's SRV priority.
func (s Service) Priority() uint16 { return s.priority }

// Weight returns the service's SRV weight.
func (s Service) Weight() uint16 { return s.weight }

// Addrs returns the discovered addresses. The returned slice is a copy;
// callers may mutate it without affecting the Service.
func (s Service) Addrs() []netip.Addr { return s.addrs }

// Text returns the discovered TXT key/value pairs. The returned map is a
// copy; callers may mutate it without affecting the Service.
func (s Service) Text() map[string]string { return s.text }

// TTL returns the discovered SRV TTL.
func (s Service) TTL() time.Duration { return s.ttl }

// ServiceBuilder builds a discovered-Service value.
type ServiceBuilder struct {
	s Service
}

// NewServiceBuilder returns a fresh ServiceBuilder.
func NewServiceBuilder() *ServiceBuilder { return &ServiceBuilder{} }

// Instance sets the instance name.
func (b *ServiceBuilder) Instance(v string) *ServiceBuilder { b.s.instance = v; return b }

// Type sets the service type name.
func (b *ServiceBuilder) Type(v wire.Name) *ServiceBuilder { b.s.typ = v; return b }

// Host sets the target host name.
func (b *ServiceBuilder) Host(v wire.Name) *ServiceBuilder { b.s.host = v; return b }

// Port sets the service port.
func (b *ServiceBuilder) Port(v uint16) *ServiceBuilder { b.s.port = v; return b }

// Priority sets the SRV priority.
func (b *ServiceBuilder) Priority(v uint16) *ServiceBuilder { b.s.priority = v; return b }

// Weight sets the SRV weight.
func (b *ServiceBuilder) Weight(v uint16) *ServiceBuilder { b.s.weight = v; return b }

// Addrs sets the discovered address list.
func (b *ServiceBuilder) Addrs(v []netip.Addr) *ServiceBuilder { b.s.addrs = v; return b }

// Text sets the TXT key/value pairs.
func (b *ServiceBuilder) Text(v map[string]string) *ServiceBuilder { b.s.text = v; return b }

// TTL sets the SRV TTL.
func (b *ServiceBuilder) TTL(v time.Duration) *ServiceBuilder { b.s.ttl = v; return b }

// Build returns the assembled Service and resets b to the zero
// state — single-shot semantics. The Service's slice/map fields
// ALIAS the values passed to the builder's setters.
//
// Service is a pure value carrier populated from already-parsed
// mDNS records, so Build cannot fail. The signature is intentionally
// infallible.
func (b *ServiceBuilder) Build() Service {
	out := b.s
	*b = ServiceBuilder{}
	return out
}

// BuildBrowseQuery constructs a PTR query for the given service type
// (e.g. "_http._tcp" or "_http._tcp.local"). The result can be marshalled
// directly and sent via any UDP path.
func BuildBrowseQuery(service string) (wire.Message, error) {
	name, err := serviceName(service)
	if err != nil {
		return wire.Message{}, err
	}
	return wire.NewMessageBuilder().
		ID(0). // RFC 6762 §18.1 — mDNS requests use ID 0.
		RecursionDesired(false).
		Question(wire.NewQuestion(name, rrtype.PTR)).
		Build()
}

// ParseBrowseResponse extracts the Service entries described by a single
// mDNS response. Multiple responses may need to be merged by the caller
// (additional sections from later responses can fill in addresses for
// hosts whose SRV came in earlier).
func ParseBrowseResponse(m wire.Message) []Service {
	srvByOwner := map[string]rdata.SRV{}
	srvTTLs := map[string]time.Duration{}
	txtByOwner := map[string][]string{}
	addrsByHost := map[string][]netip.Addr{}

	scanner := func(rec wire.Record) {
		key := rec.Name().String()
		switch v := rec.RData().(type) {
		case rdata.SRV:
			srvByOwner[key] = v
			srvTTLs[key] = rec.TTL()
		case rdata.TXT:
			txtByOwner[key] = append(txtByOwner[key], v.Strings()...)
		case rdata.A:
			addrsByHost[key] = append(addrsByHost[key], v.Addr())
		case rdata.AAAA:
			addrsByHost[key] = append(addrsByHost[key], v.Addr())
		}
	}
	for _, rec := range m.Answers() {
		scanner(rec)
	}
	for _, rec := range m.Additionals() {
		scanner(rec)
	}

	var out []Service
	for _, rec := range m.Answers() {
		ptr, ok := wire.RDataAs[rdata.PTR](rec)
		if !ok {
			continue
		}
		instanceName := ptr.Target()
		key := instanceName.String()
		s, haveSRV := srvByOwner[key]
		if !haveSRV {
			continue
		}
		svc := NewServiceBuilder().
			Instance(leadingLabel(instanceName)).
			Type(rec.Name()).
			Host(s.Target()).
			Port(s.Port()).
			Priority(s.Priority()).
			Weight(s.Weight()).
			Addrs(append([]netip.Addr(nil), addrsByHost[s.Target().String()]...)).
			Text(parseTXT(txtByOwner[key])).
			TTL(srvTTLs[key]).
			Build()
		out = append(out, svc)
	}
	return out
}

// Browse sends a multicast PTR query for the named service type and
// collects responses until ctx is cancelled or its deadline expires.
// Callers SHOULD wrap ctx with context.WithTimeout to bound the wait —
// mDNS browses by their nature are open-ended.
//
// Browse deduplicates services by (instance, type) across responses.
func Browse(ctx context.Context, service string, opts ...BrowseOption) ([]Service, error) {
	cfg := browseConfig{}
	for _, opt := range opts {
		switch opt.Ident() {
		case identBrowseConn{}:
			cfg.openConn = option.MustGet[func() (net.PacketConn, error)](opt)
		case identMulticastInterface{}:
			cfg.multiIfce = option.MustGet[*net.Interface](opt)
		}
	}
	if cfg.openConn == nil {
		ifce := cfg.multiIfce
		cfg.openConn = func() (net.PacketConn, error) { return openMulticast(ifce) }
	}

	q, err := BuildBrowseQuery(service)
	if err != nil {
		return nil, err
	}
	msg, err := wire.Pack(q)
	if err != nil {
		return nil, err
	}

	conn, err := cfg.openConn()
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// When the caller has pinned an interface for receive, also pin it
	// for transmit. Without IP_MULTICAST_IF the kernel routes 224.0.0.251
	// out the default-route interface, which on a multi-homed host
	// (VPN, container bridge) is unrelated to the receive interface —
	// peers on the intended LAN never see the question. Best-effort:
	// any error from the type assertion or the syscall just means we
	// fall back to kernel default, matching the previous behaviour.
	if cfg.multiIfce != nil {
		if uc, ok := conn.(*net.UDPConn); ok {
			pc := ipv4.NewPacketConn(uc)
			_ = pc.SetMulticastInterface(cfg.multiIfce)
		}
	}

	dst := &net.UDPAddr{IP: net.ParseIP(GroupV4), Port: Port}
	if _, err := conn.WriteTo(msg, dst); err != nil {
		return nil, fmt.Errorf("mdns: send: %w", err)
	}

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(dl)
	}

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-stop:
		}
	}()

	merged := map[string]Service{}
	buf := make([]byte, 9000)
	for {
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}
		// RFC 6762 §11 requires receivers to ignore mDNS traffic whose
		// source is not on-link. We can't see the IP TTL or interface
		// from a vanilla net.PacketConn, so we approximate by demanding
		// a non-public source address: link-local, RFC 1918, ULA, or
		// loopback. An off-link forgery from a globally-routable peer
		// is the attack we're closing here — a misconfigured LAN with
		// a globally-routable host will still work via the broader
		// allow-list.
		if !linkLocalishSource(src) {
			continue
		}
		resp, err := wire.Unpack(buf[:n])
		if err != nil {
			continue
		}
		for _, svc := range ParseBrowseResponse(resp) {
			key := svc.instance + "|" + svc.typ.String()
			merged[key] = svc
		}
	}
	if len(merged) == 0 {
		return nil, ErrNoResponse
	}
	out := make([]Service, 0, len(merged))
	for _, s := range merged {
		out = append(out, s)
	}
	return out, nil
}

// linkLocalishSource reports whether src is plausibly an on-link mDNS
// peer per the RFC 6762 §11 requirement. Returns false for nil / unknown
// address types so a future net.Addr family does not silently accept
// arbitrary sources.
func linkLocalishSource(src net.Addr) bool {
	ua, ok := src.(*net.UDPAddr)
	if !ok {
		return false
	}
	addr, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	switch {
	case addr.IsLoopback():
		return true
	case addr.IsLinkLocalUnicast():
		return true
	case addr.IsPrivate():
		return true
	}
	return false
}

func openMulticast(ifce *net.Interface) (*net.UDPConn, error) {
	addr := &net.UDPAddr{IP: net.ParseIP(GroupV4), Port: Port}
	return net.ListenMulticastUDP("udp4", ifce, addr)
}

// serviceName normalises a user-supplied service spec. Accepts "_http._tcp",
// "_http._tcp.local", or "_http._tcp.local." and returns the msg form.
func serviceName(service string) (wire.Name, error) {
	s := strings.TrimSuffix(service, ".")
	if !strings.HasSuffix(s, ".local") {
		s = s + ".local"
	}
	return wire.ParseName(s)
}

func leadingLabel(n wire.Name) string {
	for l := range n.Labels() {
		return string(l)
	}
	return ""
}

// parseTXT decodes service-discovery key-value pairs from TXT strings
// per RFC 6763 §6.
func parseTXT(strs []string) map[string]string {
	out := map[string]string{}
	for _, s := range strs {
		if before, after, ok := strings.Cut(s, "="); ok {
			out[before] = after
		} else if s != "" {
			out[s] = ""
		}
	}
	return out
}
