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
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/option/v3"
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
func (s Service) Addrs() []netip.Addr { return slices.Clone(s.addrs) }

// Text returns the discovered TXT key/value pairs. The returned map is a
// copy; callers may mutate it without affecting the Service.
func (s Service) Text() map[string]string { return maps.Clone(s.text) }

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

// Build returns the assembled Service.
func (b *ServiceBuilder) Build() (Service, error) {
	return b.s, nil
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
		switch rec.Type() {
		case rrtype.SRV:
			if s, ok := rec.RData().(rdata.SRV); ok {
				srvByOwner[key] = s
				srvTTLs[key] = rec.TTL()
			}
		case rrtype.TXT:
			if t, ok := rec.RData().(rdata.TXT); ok {
				txtByOwner[key] = append(txtByOwner[key], t.Strings()...)
			}
		case rrtype.A:
			if a, ok := rec.RData().(rdata.A); ok {
				addrsByHost[key] = append(addrsByHost[key], a.Addr())
			}
		case rrtype.AAAA:
			if a, ok := rec.RData().(rdata.AAAA); ok {
				addrsByHost[key] = append(addrsByHost[key], a.Addr())
			}
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
		if rec.Type() != rrtype.PTR {
			continue
		}
		ptr, ok := rec.RData().(rdata.PTR)
		if !ok {
			continue
		}
		instanceName := ptr.PtrDName()
		key := instanceName.String()
		s, haveSRV := srvByOwner[key]
		if !haveSRV {
			continue
		}
		svc, _ := NewServiceBuilder().
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
	cfg := browseConfig{
		openConn: func() (net.PacketConn, error) { return openMulticast() },
	}
	for _, opt := range opts {
		switch opt.Ident() {
		case identBrowseConn{}:
			cfg.openConn = option.MustGet[func() (net.PacketConn, error)](opt)
		}
	}

	q, err := BuildBrowseQuery(service)
	if err != nil {
		return nil, err
	}
	msg, err := wire.Marshal(q)
	if err != nil {
		return nil, err
	}

	conn, err := cfg.openConn()
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

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
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}
		resp, err := wire.Unmarshal(buf[:n])
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

func openMulticast() (*net.UDPConn, error) {
	addr := &net.UDPAddr{IP: net.ParseIP(GroupV4), Port: Port}
	return net.ListenMulticastUDP("udp4", nil, addr)
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
