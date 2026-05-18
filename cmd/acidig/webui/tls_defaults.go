package webui

import "net/netip"

// publicDefaultUpstreams is the always-on seed list for the upstream
// dropdown. Each entry is a major public DNS resolver that speaks
// every transport this UI offers — plain UDP/53, TCP/53, DoT/853,
// and DoH — so the user can switch transports freely without
// discovering that their system resolver only supports one of them.
//
// Order matters: it's the order the dropdown renders. 1.1.1.1 comes
// first as the default selection because it's the lowest-friction
// for the rest of the auto-fill machinery (well-known TLS name,
// well-known DoH endpoint).
var publicDefaultUpstreams = []netip.AddrPort{
	netip.MustParseAddrPort("1.1.1.1:53"),
	netip.MustParseAddrPort("8.8.8.8:53"),
	netip.MustParseAddrPort("9.9.9.9:53"),
}

// wellKnownDoTNames maps the IP literal of widely-used public DoT
// resolvers to the TLS server name their certificates carry. The web
// UI uses this map to fill the SNI / verification name when the user
// picks DoT against one of these endpoints, so they don't have to
// know or type the name themselves.
//
// Mirrored in assets/app.js purely for visual feedback (auto-fill
// happens as the user picks the upstream). This map is the source of
// truth — the server applies it regardless of what the client sent.
var wellKnownDoTNames = map[netip.Addr]string{
	netip.MustParseAddr("1.1.1.1"):         "cloudflare-dns.com",
	netip.MustParseAddr("1.0.0.1"):         "cloudflare-dns.com",
	netip.MustParseAddr("8.8.8.8"):         "dns.google",
	netip.MustParseAddr("8.8.4.4"):         "dns.google",
	netip.MustParseAddr("9.9.9.9"):         "dns.quad9.net",
	netip.MustParseAddr("149.112.112.112"): "dns.quad9.net",
	netip.MustParseAddr("8.26.56.26"):      "dns.cleanbrowsing.org",
	netip.MustParseAddr("94.140.14.14"):    "dns.adguard-dns.com",
	netip.MustParseAddr("94.140.15.15"):    "dns.adguard-dns.com",
}

// wellKnownDoHURLs maps the IP literal of widely-used public DoH
// resolvers to the URL their server speaks DoH on. URLs use the IP
// literal as the host (rather than the hostname) because every entry
// here has its IP in the certificate's SAN, so the connection goes
// to the upstream the user picked without an interstitial DNS
// resolution for the URL hostname — the alternative would mean
// resolving e.g. cloudflare-dns.com via the system resolver, which
// can land on a different POP than the user thought they chose.
var wellKnownDoHURLs = map[netip.Addr]string{
	netip.MustParseAddr("1.1.1.1"):         "https://1.1.1.1/dns-query",
	netip.MustParseAddr("1.0.0.1"):         "https://1.0.0.1/dns-query",
	netip.MustParseAddr("8.8.8.8"):         "https://8.8.8.8/dns-query",
	netip.MustParseAddr("8.8.4.4"):         "https://8.8.4.4/dns-query",
	netip.MustParseAddr("9.9.9.9"):         "https://9.9.9.9/dns-query",
	netip.MustParseAddr("149.112.112.112"): "https://149.112.112.112/dns-query",
}

// pickDoHURL resolves the DoH URL for a query. Priority:
//
//  1. An explicit URL from the request — always honoured.
//  2. The well-known map keyed on the upstream IP — provides a working
//     URL for the public resolvers the dropdown seeds.
//  3. Empty string with ok=false — the caller surfaces this as a
//     friendly error rather than constructing a URL that might 404.
func pickDoHURL(explicit string, upstream netip.AddrPort) (string, bool) {
	if explicit != "" {
		return explicit, true
	}
	if url, found := wellKnownDoHURLs[upstream.Addr()]; found {
		return url, true
	}
	return "", false
}

// pickTLSName resolves the effective TLS server name and certificate-
// verification mode for a DoT request. Priority:
//
//  1. An explicit name from the request — always honoured, verification on.
//  2. The well-known map keyed on the upstream IP — provides a verified
//     name for the public resolvers users actually pick from a dropdown.
//  3. Fallback: use the IP literal as the SNI and disable verification.
//     The TLS handshake still encrypts, but the cert isn't checked.
//     This keeps the UI working for arbitrary DoT endpoints without
//     pestering the user for a name.
//
// The boolean return is true when verification was skipped, so the
// caller can surface that fact in the response.
func pickTLSName(explicit string, upstream netip.AddrPort) (name string, insecure bool) {
	if explicit != "" {
		return explicit, false
	}
	if known, ok := wellKnownDoTNames[upstream.Addr()]; ok {
		return known, false
	}
	return upstream.Addr().String(), true
}
