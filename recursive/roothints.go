package recursive

import "net/netip"

// iANARootHints is the IANA root server snapshot bundled with the
// resolver as a last-resort bootstrap list. Source:
// https://www.iana.org/domains/root/servers
//
// This list is consulted only when the operator did not supply
// [WithRoots] AND root priming is either disabled or has not yet
// completed a successful refresh. As soon as priming returns a fresh
// authoritative list the in-memory roots are replaced — see
// [recursive.Prime] / [recursive.RunMaintenance].
//
// The snapshot drifts as IANA reorganises operators; long-running
// daemons should enable [WithRootPriming] so the live list stays
// current without an operator restart.
var iANARootHints = []netip.AddrPort{
	netip.MustParseAddrPort("198.41.0.4:53"), // a.root-servers.net
	netip.MustParseAddrPort("[2001:503:ba3e::2:30]:53"),
	netip.MustParseAddrPort("170.247.170.2:53"), // b.root-servers.net
	netip.MustParseAddrPort("[2801:1b8:10::b]:53"),
	netip.MustParseAddrPort("192.33.4.12:53"), // c
	netip.MustParseAddrPort("[2001:500:2::c]:53"),
	netip.MustParseAddrPort("199.7.91.13:53"), // d
	netip.MustParseAddrPort("[2001:500:2d::d]:53"),
	netip.MustParseAddrPort("192.203.230.10:53"), // e
	netip.MustParseAddrPort("[2001:500:a8::e]:53"),
	netip.MustParseAddrPort("192.5.5.241:53"), // f
	netip.MustParseAddrPort("[2001:500:2f::f]:53"),
	netip.MustParseAddrPort("192.112.36.4:53"), // g
	netip.MustParseAddrPort("[2001:500:12::d0d]:53"),
	netip.MustParseAddrPort("198.97.190.53:53"), // h
	netip.MustParseAddrPort("[2001:500:1::53]:53"),
	netip.MustParseAddrPort("192.36.148.17:53"), // i
	netip.MustParseAddrPort("[2001:7fe::53]:53"),
	netip.MustParseAddrPort("192.58.128.30:53"), // j
	netip.MustParseAddrPort("[2001:503:c27::2:30]:53"),
	netip.MustParseAddrPort("193.0.14.129:53"), // k
	netip.MustParseAddrPort("[2001:7fd::1]:53"),
	netip.MustParseAddrPort("199.7.83.42:53"), // l
	netip.MustParseAddrPort("[2001:500:9f::42]:53"),
	netip.MustParseAddrPort("202.12.27.33:53"), // m
	netip.MustParseAddrPort("[2001:dc3::35]:53"),
}
