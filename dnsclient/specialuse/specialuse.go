// Package specialuse implements the policy from RFC 6761 §6 (and the
// later additions for .onion in RFC 7686 and .alt in RFC 9476). A
// Resolver consults Disposition() before issuing a network query and
// short-circuits names whose semantics are reserved by the IETF.
package specialuse

import (
	"net/netip"
	"strings"

	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
)

// Disposition describes how a Resolver should treat a special-use name.
type Disposition int

const (
	// Pass: the name is not special; send it on as usual.
	Pass Disposition = iota
	// SynthLocalhost: synthesise a loopback answer (RFC 6761 §6.3).
	// 127.0.0.1 for type A, ::1 for type AAAA, NODATA otherwise.
	SynthLocalhost
	// Refuse: the name MUST NOT be sent to an authoritative server.
	// Resolvers SHOULD return NXDOMAIN immediately.
	Refuse
	// Local: the name belongs to the multicast-DNS link-local space.
	// Resolvers without mDNS support SHOULD return NXDOMAIN.
	Local
)

// For returns the disposition for n. The check is suffix-based and
// case-insensitive; names equal to a reserved suffix are matched as well
// as names below it.
//
// Per RFC 6761 §6.5, application software SHOULD NOT special-case
// "example", "example.com", "example.net", or "example.org" — those are
// reserved against future allocation but otherwise resolve normally.
func For(n dnsname.Name) Disposition {
	if !n.IsValid() {
		return Pass
	}
	s := strings.ToLower(n.String())
	switch {
	case s == "localhost." || strings.HasSuffix(s, ".localhost."):
		return SynthLocalhost
	case s == "local." || strings.HasSuffix(s, ".local."):
		return Local
	case suffixIs(s, "invalid."), suffixIs(s, "test."),
		suffixIs(s, "onion."), suffixIs(s, "alt."):
		return Refuse
	}
	return Pass
}

func suffixIs(name, reserved string) bool {
	if name == reserved {
		return true
	}
	return strings.HasSuffix(name, "."+reserved)
}

// LoopbackForType returns the synthetic addresses RFC 6761 §6.3 assigns
// to the localhost zone for a given QTYPE: 127.0.0.1 for A, ::1 for AAAA.
// Returns an empty slice for any other type.
func LoopbackForType(t rrtype.Type) []netip.Addr {
	switch t {
	case rrtype.A:
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	case rrtype.AAAA:
		return []netip.Addr{netip.MustParseAddr("::1")}
	default:
		return nil
	}
}
