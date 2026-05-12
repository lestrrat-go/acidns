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
// Client from the root acidns package and wrap it with TLS yourself,
// or use [NewKeepAliveClient] (DoT-native keep-alive).
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
// The TLS floor is TLS 1.3 (RFC 7858 §9 SHOULD use 1.3). A
// caller-supplied tls.Config whose MinVersion is unset or set below
// 1.3 is silently raised to 1.3.
//
// Use WithTLSConfig to pin certificate roots, supply a session-resume
// cache, or enable mTLS. Use WithServerName to set the SNI / cert
// verification name when targeting an IP literal whose certificate is
// bound to a hostname.
package dot

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/internal/spki"
	"github.com/lestrrat-go/acidns/internal/streamframe"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/option/v3"
)

type Client struct {
	addr      netip.AddrPort
	timeout   time.Duration
	tlsConfig *tls.Config
	padding   bool
}

// NewClient returns a *Client that talks DoT to addr. addr is typically
// "host:853" — DoT does not auto-default the port, but addresses
// without a port resolve to 853 in the higher-level Resolver wiring.
// *Client satisfies [acidns.Exchanger]; the concrete pointer is
// returned so callers can reach implementation-specific affordances
// without an interface assertion.
func NewClient(addr netip.AddrPort, opts ...Option) (*Client, error) {
	if !addr.IsValid() {
		return nil, ErrInvalidAddress
	}
	c := config{timeout: 10 * time.Second, padding: true}
	for _, o := range opts {
		switch o.Ident() {
		case identTimeout{}:
			c.timeout = option.MustGet[time.Duration](o)
		case identTLSConfig{}:
			c.tlsConfig = option.MustGet[*tls.Config](o)
		case identServerName{}:
			c.serverName = option.MustGet[string](o)
		case identPadding{}:
			c.padding = option.MustGet[bool](o)
		case identInsecure{}:
			c.insecure = option.MustGet[bool](o)
		case identSPKIPin{}:
			c.spkiPins = append(c.spkiPins, option.MustGet[[]byte](o))
		}
	}
	for _, p := range c.spkiPins {
		if len(p) != spki.HashSize {
			return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidSPKIPin, len(p))
		}
	}

	var tcfg *tls.Config
	if c.tlsConfig != nil {
		// Refuse a caller-supplied tls.Config that already disables
		// cert verification unless WithInsecure(true) was also passed.
		// Mirrors the DoH posture (doh.go: TLSClientConfig check) so
		// the rule is uniform across encrypted transports.
		if c.tlsConfig.InsecureSkipVerify && !c.insecure {
			return nil, ErrInsecureTLSConfig
		}
		tcfg = c.tlsConfig.Clone()
	} else {
		tcfg = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	// RFC 7858 §9 SHOULD use TLS 1.3. Any caller-supplied lower floor
	// (including the explicit TLS 1.2 case) is silently raised — DoT is
	// privacy-by-encryption and the older AEAD-less ciphersuites are not
	// fit for that use.
	if tcfg.MinVersion < tls.VersionTLS13 {
		tcfg.MinVersion = tls.VersionTLS13
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
	if tcfg.ServerName == "" && !isHostnameAddr(addr) && !c.insecure {
		return nil, fmt.Errorf("%w (or *tls.Config.ServerName)", ErrServerNameRequired)
	}
	if c.insecure {
		tcfg.InsecureSkipVerify = true
	}
	// SPKI pin enforcement runs AFTER PKIX validation (which fires
	// first inside crypto/tls). When the caller supplied their own
	// VerifyConnection via WithTLSConfig, run theirs first so any
	// custom check they configured still gates the handshake.
	if len(c.spkiPins) > 0 {
		prev := tcfg.VerifyConnection
		pins := c.spkiPins
		tcfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if prev != nil {
				if err := prev(cs); err != nil {
					return err
				}
			}
			return verifySPKIPin(cs, pins)
		}
	}

	return &Client{addr: addr, timeout: c.timeout, tlsConfig: tcfg, padding: c.padding}, nil
}

// verifySPKIPin checks the leaf certificate's SubjectPublicKeyInfo
// SHA-256 hash against the registered pins (RFC 7858 §4.2). At least
// one pin must match. Constant-time comparison is used uniformly with
// the rest of the codebase's crypto pattern even though pins are
// public material.
func verifySPKIPin(cs tls.ConnectionState, pins [][]byte) error {
	if len(cs.PeerCertificates) == 0 {
		return ErrNoPeerCertificate
	}
	got := spki.Hash(cs.PeerCertificates[0])
	for _, pin := range pins {
		if subtle.ConstantTimeCompare(got[:], pin) == 1 {
			return nil
		}
	}
	return ErrSPKIPinMismatch
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

func (e *Client) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
	if e.padding {
		q = wire.PadEncrypted(q)
	}
	d := tls.Dialer{Config: e.tlsConfig, NetDialer: &net.Dialer{Timeout: e.timeout}}
	conn, err := d.DialContext(ctx, "tcp", e.addr.String())
	if err != nil {
		return wire.Message{}, fmt.Errorf("dot: dial %s: %w", e.addr, err)
	}
	resp, err := streamframe.Exchange(ctx, conn, q, e.timeout)
	if err != nil {
		return wire.Message{}, err
	}
	acidns.SetExchangeServer(ctx, e.addr)
	return resp, nil
}

// Stream sends q over a fresh TLS connection and returns a MessageStream
// from which the caller pulls responses. Implements XoT (RFC 9103) when
// q is an AXFR/IXFR query.
func (e *Client) Stream(ctx context.Context, q wire.Message) (acidns.MessageStream, error) {
	if e.padding {
		q = wire.PadEncrypted(q)
	}
	d := tls.Dialer{Config: e.tlsConfig, NetDialer: &net.Dialer{Timeout: e.timeout}}
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
