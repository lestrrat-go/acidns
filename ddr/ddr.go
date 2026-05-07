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

// ResolverDomain is the special name clients query to discover designated
// resolvers (RFC 9462 §4).
var ResolverDomain = wire.MustParseName("_dns.resolver.arpa")

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
	Priority  uint16
	Target    wire.Name
	Protocol  Protocol
	ALPN      []string
	Port      uint16 // 0 when unspecified
	DOHPath   string // empty for non-DoH endpoints
	IPv4Hints []netip.Addr
	IPv6Hints []netip.Addr
}

// Discover queries _dns.resolver.arpa via r and returns the Endpoints sorted
// by priority (lowest first; priority 0 has special meaning per RFC 9460 and
// is filtered out — those are AliasMode SVCB entries).
func Discover(ctx context.Context, r acidns.Resolver) ([]Endpoint, error) {
	ans, err := r.Resolve(ctx, ResolverDomain, rrtype.SVCB)
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
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out, nil
}

func endpointFromSVCB(s rdata.SVCB) Endpoint {
	e := Endpoint{
		Priority: s.Priority(),
		Target:   s.Target(),
		ALPN:     s.ALPN(),
	}
	if p, ok := s.Port(); ok {
		e.Port = p
	}
	if path, ok := s.DOHPath(); ok {
		e.DOHPath = path
	}
	e.IPv4Hints = s.IPv4Hints()
	e.IPv6Hints = s.IPv6Hints()
	e.Protocol = inferProtocol(e.ALPN, e.DOHPath)
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
