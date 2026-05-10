// Package ddr discovers Designated Resolvers per RFC 9462. Clients call
// [Discover] with a Resolver bound to the unencrypted resolver they
// currently use AND the bootstrap resolver's address. Discover queries
// _dns.resolver.arpa. for SVCB records, parses the SvcParams
// (RFC 9461), and returns one Endpoint per designated alternative
// transport — but only those whose IPv4Hints/IPv6Hints contain the
// bootstrap address (RFC 9462 §6.2 "Verified Discovery").
//
// The bootstrap-bound API is the safe default: returning unfiltered
// endpoints lets a downgrade attacker on the unsigned _dns.resolver.arpa
// path point clients at an upstream they control. [DiscoverUnverified]
// is provided for callers that want to do the IP-hint check themselves
// (or accept the downgrade risk knowingly), and is named to make that
// trade-off explicit at the call site.
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

// Discover queries _dns.resolver.arpa via r and returns the
// designated-resolver Endpoints whose IPv4Hints or IPv6Hints contain
// bootstrap (the address of the unencrypted resolver the caller is
// currently using). RFC 9462 §6.2 "Verified Discovery" requires this
// match before promoting traffic to the encrypted endpoint; without
// it, a man-in-the-middle on the unsigned _dns.resolver.arpa path can
// redirect clients to an attacker-controlled upstream.
//
// Priority-0 (AliasMode) responses are filtered out; the remaining
// endpoints are sorted by priority (lowest first).
//
// Returns an empty slice (no error) when no endpoint advertises the
// bootstrap address — this is operationally indistinguishable from
// "no DDR available", which is the safe default.
func Discover(ctx context.Context, r acidns.Resolver, bootstrap netip.Addr) ([]Endpoint, error) {
	all, err := DiscoverUnverified(ctx, r)
	if err != nil {
		return nil, err
	}
	if !bootstrap.IsValid() {
		return nil, errInvalidBootstrap
	}
	bootstrap = bootstrap.Unmap()
	out := all[:0]
	for _, e := range all {
		if endpointMatchesBootstrap(e, bootstrap) {
			out = append(out, e)
		}
	}
	return out, nil
}

// DiscoverUnverified is the unsafe variant: it returns every
// designated-resolver endpoint advertised on _dns.resolver.arpa
// without filtering by bootstrap address. The caller MUST do the
// RFC 9462 §6.2 IP-hint match itself (or have an out-of-band reason
// to trust the response, e.g. a DNSSEC chain that the caller
// validated). Prefer [Discover] unless you specifically need the
// raw set.
func DiscoverUnverified(ctx context.Context, r acidns.Resolver) ([]Endpoint, error) {
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

// endpointMatchesBootstrap reports whether e advertises bootstrap in
// either its IPv4Hints or IPv6Hints. Hints are compared after Unmap
// so a v4-mapped bootstrap matches against an IPv4 hint and vice versa.
func endpointMatchesBootstrap(e Endpoint, bootstrap netip.Addr) bool {
	if bootstrap.Is4() {
		for _, a := range e.ipv4Hints {
			if a.Unmap() == bootstrap {
				return true
			}
		}
		return false
	}
	for _, a := range e.ipv6Hints {
		if a.Unmap() == bootstrap {
			return true
		}
	}
	return false
}

var errInvalidBootstrap = errInvalid("ddr: bootstrap address is invalid")

type errInvalid string

func (e errInvalid) Error() string { return string(e) }

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
