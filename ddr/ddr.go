// Package ddr discovers Designated Resolvers per RFC 9462. Clients call
// Discover with a Resolver bound to the unencrypted resolver they currently
// use; Discover queries the special name "_dns.resolver.arpa." for SVCB
// records, parses the SvcParams (RFC 9461), and returns one Endpoint per
// designated alternative transport.
//
// Validation against the IP-hints constraint of RFC 9462 §4 (the discovered
// endpoint's address must match the address of the original resolver, or
// be authenticated some other way) is the caller's responsibility — the
// Endpoint's IPv4Hints / IPv6Hints expose the candidate set so callers
// can compare against their bootstrap address.
package ddr

import (
	"context"
	"net/netip"
	"sort"
	"strings"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// resolverDomainName is the special name clients query to discover
// designated resolvers (RFC 9462 §4). Computed once at package init.
var resolverDomainName = wire.MustParseName("_dns.resolver.arpa")

// ResolverDomain returns the DDR discovery name as a fresh
// [wire.Name] value. The previous shape exposed a package-level var
// that any caller could reassign; the function form is non-mutable
// by construction.
func ResolverDomain() wire.Name { return resolverDomainName }

// Protocol identifies the encrypted transport an endpoint advertises.
type Protocol uint8

const (
	ProtoUnknown Protocol = iota
	ProtoDoT
	ProtoDoH
	ProtoDoQ
)

func (p Protocol) String() string {
	switch p {
	case ProtoDoT:
		return "dot"
	case ProtoDoH:
		return "doh"
	case ProtoDoQ:
		return "doq"
	}
	return "unknown"
}

// Endpoint is one designated-resolver alternative.
type Endpoint struct {
	priority  uint16
	target    wire.Name
	protocol  Protocol
	alpn      []string
	port      uint16
	dohPath   string
	ipv4Hints []netip.Addr
	ipv6Hints []netip.Addr
}

// Priority returns the endpoint's SVCB priority (lower means preferred).
func (e Endpoint) Priority() uint16 { return e.priority }

// Target returns the endpoint's target name.
func (e Endpoint) Target() wire.Name { return e.target }

// Protocol returns the encrypted transport the endpoint advertises.
func (e Endpoint) Protocol() Protocol { return e.protocol }

// ALPN returns the ALPN identifiers advertised by the endpoint.
func (e Endpoint) ALPN() []string { return e.alpn }

// Port returns the endpoint's port; 0 when unspecified.
func (e Endpoint) Port() uint16 { return e.port }

// DOHPath returns the DoH URI template path; empty for non-DoH endpoints.
func (e Endpoint) DOHPath() string { return e.dohPath }

// IPv4Hints returns the SVCB IPv4 address hints.
func (e Endpoint) IPv4Hints() []netip.Addr { return e.ipv4Hints }

// IPv6Hints returns the SVCB IPv6 address hints.
func (e Endpoint) IPv6Hints() []netip.Addr { return e.ipv6Hints }

// EndpointBuilder builds an Endpoint with the typed-setter pattern.
type EndpointBuilder struct {
	e Endpoint
}

// NewEndpointBuilder returns a fresh EndpointBuilder.
func NewEndpointBuilder() *EndpointBuilder { return &EndpointBuilder{} }

// Priority sets the SVCB priority.
func (b *EndpointBuilder) Priority(v uint16) *EndpointBuilder { b.e.priority = v; return b }

// Target sets the target name.
func (b *EndpointBuilder) Target(v wire.Name) *EndpointBuilder { b.e.target = v; return b }

// Protocol sets the protocol.
func (b *EndpointBuilder) Protocol(v Protocol) *EndpointBuilder { b.e.protocol = v; return b }

// ALPN sets the ALPN identifiers.
func (b *EndpointBuilder) ALPN(v []string) *EndpointBuilder { b.e.alpn = v; return b }

// Port sets the port (0 = unspecified).
func (b *EndpointBuilder) Port(v uint16) *EndpointBuilder { b.e.port = v; return b }

// DOHPath sets the DoH URI template path.
func (b *EndpointBuilder) DOHPath(v string) *EndpointBuilder { b.e.dohPath = v; return b }

// IPv4Hints sets the IPv4 address hints.
func (b *EndpointBuilder) IPv4Hints(v []netip.Addr) *EndpointBuilder { b.e.ipv4Hints = v; return b }

// IPv6Hints sets the IPv6 address hints.
func (b *EndpointBuilder) IPv6Hints(v []netip.Addr) *EndpointBuilder { b.e.ipv6Hints = v; return b }

// Build returns the configured Endpoint.
func (b *EndpointBuilder) Build() (Endpoint, error) {
	return b.e, nil
}

// Discover queries _dns.resolver.arpa via r and returns the Endpoints sorted
// by priority (lowest first; priority 0 has special meaning per RFC 9460 and
// is filtered out — those are AliasMode SVCB entries).
func Discover(ctx context.Context, r acidns.Resolver) ([]Endpoint, error) {
	ans, err := r.Resolve(ctx, resolverDomainName, rrtype.SVCB)
	if err != nil {
		return nil, err
	}
	var out []Endpoint
	for _, rec := range ans.Records() {
		if rec.Type() != rrtype.SVCB {
			continue
		}
		s, ok := rec.RData().(rdata.SVCB)
		if !ok {
			continue
		}
		if s.Priority() == 0 {
			// AliasMode — clients should chase Target. RFC 9462 §4.2 keeps
			// it simple: ignore for now and let the caller follow up.
			continue
		}
		out = append(out, endpointFromSVCB(s))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].priority < out[j].priority })
	return out, nil
}

func endpointFromSVCB(s rdata.SVCB) Endpoint {
	b := NewEndpointBuilder().
		Priority(s.Priority()).
		Target(s.Target()).
		ALPN(s.ALPN()).
		IPv4Hints(s.IPv4Hints()).
		IPv6Hints(s.IPv6Hints())
	if p, ok := s.Port(); ok {
		b.Port(p)
	}
	if path, ok := s.DOHPath(); ok {
		b.DOHPath(path)
	}
	b.Protocol(inferProtocol(s.ALPN(), b.e.dohPath))
	e, _ := b.Build()
	return e
}

func inferProtocol(alpn []string, dohpath string) Protocol {
	if dohpath != "" {
		return ProtoDoH
	}
	for _, a := range alpn {
		switch strings.ToLower(a) {
		case "h2", "h3", "http/1.1":
			return ProtoDoH
		case "doq":
			return ProtoDoQ
		case "dot":
			return ProtoDoT
		}
	}
	return ProtoUnknown
}
