// Package dot implements DNS over TLS (RFC 7858) — encrypted DNS on
// port 853 over a TLS-wrapped TCP connection. Use it as the substrate
// for a privacy-preserving stub resolver, or as the upstream of a
// caching forwarder.
//
// # Connection model
//
// Each Exchange opens a fresh TLS connection on top of TCP. Connection
// reuse, idle timeouts, and pipelining are out of scope for this
// primitive transport — for keep-alive, use the TCP keep-alive
// exchanger from the root acidns package and wrap it with TLS yourself,
// or wait for a future dot.NewKeepAlive helper.
//
// Stream returns a MessageStream so the caller can pull AXFR / IXFR
// responses (RFC 9103, "XFR over TLS") on the same connection without
// re-handshaking.
//
// # Padding
//
// Outgoing queries are padded to a 128-byte boundary per RFC 8467 §4.1
// before TLS encryption, so the encrypted record's size cannot leak
// the queried name. Disable with WithPadding(false) for byte-exact
// fixtures.
//
// # TLS
//
// Use WithTLSConfig to pin certificate roots, supply a session-resume
// cache, or enable mTLS. Use WithServerName to set the SNI / cert
// verification name when targeting an IP literal whose certificate is
// bound to a hostname.
package dot

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/internal/streamframe"
	"github.com/lestrrat-go/acidns/wire"
)

type exchanger struct {
	addr      netip.AddrPort
	timeout   time.Duration
	tlsConfig *tls.Config
	padding   bool
}

// New returns an Exchanger that talks DoT to addr. addr is typically
// "host:853" — DoT does not auto-default the port, but addresses without a
// port resolve to 853 in the higher-level Resolver wiring.
func New(addr netip.AddrPort, opts ...Option) (acidns.Exchanger, error) {
	if !addr.IsValid() {
		return nil, fmt.Errorf("dot: invalid server address")
	}
	c := config{timeout: 10 * time.Second, padding: true}
	for _, o := range opts {
		o.applyDoT(&c)
	}

	var tcfg *tls.Config
	if c.tlsConfig != nil {
		tcfg = c.tlsConfig.Clone()
	} else {
		tcfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if c.serverName != "" {
		tcfg.ServerName = c.serverName
	}
	// RFC 7858 §3.2 — DoT clients SHOULD use ALPN with the "dot"
	// identifier so multiplexed servers can disambiguate DoT from
	// other TLS-on-853 protocols. Append rather than overwrite so a
	// caller-supplied tls.Config keeping its own preferences still
	// participates in negotiation.
	if !containsALPN(tcfg.NextProtos, "dot") {
		tcfg.NextProtos = append(tcfg.NextProtos, "dot")
	}
	// An IP-literal address with no ServerName falls back to the IP as
	// SNI / cert verification name, which silently authenticates against
	// any cert that happens to include the IP — typically not what the
	// caller wants. Refuse this combination so a misuse is loud, not
	// silent. Use WithServerName or pre-configure the *tls.Config.
	if tcfg.ServerName == "" && !isHostnameAddr(addr) {
		return nil, fmt.Errorf("dot: WithServerName (or *tls.Config.ServerName) required when addr is an IP literal")
	}

	return &exchanger{addr: addr, timeout: c.timeout, tlsConfig: tcfg, padding: c.padding}, nil
}

// isHostnameAddr reports whether addr is a hostname:port form rather
// than an ip:port form. netip.AddrPort always represents a parsed IP,
// so this currently returns false for any valid AddrPort — the helper
// is here for symmetry with future hostname-aware constructors.
func isHostnameAddr(addr netip.AddrPort) bool {
	_ = addr
	return false
}

func containsALPN(list []string, p string) bool {
	return slices.Contains(list, p)
}

func (e *exchanger) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
	if e.padding {
		q = wire.PadEncrypted(q)
	}
	d := tls.Dialer{Config: e.tlsConfig, NetDialer: &net.Dialer{}}
	conn, err := d.DialContext(ctx, "tcp", e.addr.String())
	if err != nil {
		return nil, fmt.Errorf("dot: dial %s: %w", e.addr, err)
	}
	return streamframe.Exchange(ctx, conn, q, e.timeout)
}

// Stream sends q over a fresh TLS connection and returns a MessageStream
// from which the caller pulls responses. Implements XoT (RFC 9103) when
// q is an AXFR/IXFR query.
func (e *exchanger) Stream(ctx context.Context, q wire.Message) (acidns.MessageStream, error) {
	if e.padding {
		q = wire.PadEncrypted(q)
	}
	d := tls.Dialer{Config: e.tlsConfig, NetDialer: &net.Dialer{}}
	conn, err := d.DialContext(ctx, "tcp", e.addr.String())
	if err != nil {
		return nil, fmt.Errorf("dot: dial %s: %w", e.addr, err)
	}
	s, err := streamframe.NewConnStream(ctx, conn, q, e.timeout)
	if err != nil {
		return nil, fmt.Errorf("dot: %w", err)
	}
	return s, nil
}
