package webui

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// Mode toggles which surface area the UI and the /api/query handler
// expose. Basic restricts the user to a curated, "safe" set of query
// types and upstreams; Advanced unlocks everything (raw types, free-form
// upstream, alternate transports, raw wire dump).
//
// Mode is set once by acidig from its CLI flags and never mutated; the
// server-side handler re-validates every request against the configured
// mode, so a hostile client cannot bypass the gate by hand-crafting a
// POST.
type Mode int

const (
	ModeBasic Mode = iota
	ModeAdvanced
)

func (m Mode) String() string {
	if m == ModeAdvanced {
		return "advanced"
	}
	return "basic"
}

// basicQTypes is the curated allow-list of RR types exposed by the
// basic-mode UI. The list intentionally excludes ANY (amplification),
// AXFR/IXFR (zone enumeration), OPT (pseudo-RR; not queryable), and
// signing/UPDATE-side types. Order is the order the UI renders the
// dropdown.
var basicQTypes = []rrtype.Type{
	rrtype.A,
	rrtype.AAAA,
	rrtype.CNAME,
	rrtype.MX,
	rrtype.TXT,
	rrtype.NS,
	rrtype.SOA,
	rrtype.PTR,
	rrtype.SRV,
	rrtype.CAA,
	rrtype.HTTPS,
	rrtype.SVCB,
}

func basicQTypeNames() []string {
	out := make([]string, len(basicQTypes))
	for i, t := range basicQTypes {
		out[i] = t.String()
	}
	return out
}

// allowedBasicQType reports whether t is in the basic allow-list.
func allowedBasicQType(t rrtype.Type) bool {
	return slices.Contains(basicQTypes, t)
}

// allowedBasicUpstream reports whether addr is one of the upstreams the
// server was configured with. Basic mode rejects free-form addresses;
// the user must pick from /etc/resolv.conf or a --web-upstream flag.
//
// The comparison is IP-only — a configured `1.1.1.1:53` also approves
// `1.1.1.1:853` for DoT. The trust boundary is which DNS server we're
// allowed to talk to; the transport picks the right port. Without
// this, switching transports against a dropdown-supplied upstream
// would 403 because the port doesn't match the configured entry.
func allowedBasicUpstream(configured []netip.AddrPort, addr netip.AddrPort) bool {
	for _, c := range configured {
		if c.Addr() == addr.Addr() {
			return true
		}
	}
	return false
}

// validateBasic runs the basic-mode allow-list against a parsed query.
// Returns a typed error suitable for surfacing as a 400 with a clear
// message.
func validateBasic(q *parsedQuery, configured []netip.AddrPort) error {
	if !allowedBasicQType(q.qtype) {
		return fmt.Errorf("basic mode: type %s not in allow-list", q.qtype)
	}
	// All four transports are permitted in basic mode now that DoH
	// can derive its URL from the upstream IP (see pickDoHURL). The
	// configured-upstream allow-list still bounds the request — for
	// UDP/TCP/DoT directly by addr, for DoH transitively via the
	// upstream IP that pickDoHURL maps to a URL.
	switch q.transport {
	case transportUDP, transportTCP, transportDoT, transportDoH:
	default:
		return fmt.Errorf("basic mode: transport %s not allowed", q.transport)
	}
	// For DoH the upstream may be the zero AddrPort if the user
	// supplied only doh_url. Basic mode rejects that case because we
	// can't bound a free-form URL by the configured-upstream list;
	// the user must pick from the dropdown so the URL comes from the
	// well-known map.
	if q.transport == transportDoH && q.dohURL != "" {
		return fmt.Errorf("basic mode: free-form doh_url not allowed; pick an upstream from the dropdown")
	}
	if !allowedBasicUpstream(configured, q.upstream) {
		return fmt.Errorf("basic mode: upstream %s not in configured list", q.upstream)
	}
	if q.cd {
		return fmt.Errorf("basic mode: CD bit not allowed")
	}
	if !q.rd {
		return fmt.Errorf("basic mode: RD bit must be set")
	}
	if !q.edns {
		return fmt.Errorf("basic mode: EDNS must be enabled")
	}
	return nil
}
