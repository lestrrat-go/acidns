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
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
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

	// RFC 7858 §9 SHOULD use TLS 1.3; §3.2 SHOULD advertise the
	// "dot" ALPN. An IP-literal address with no ServerName falls
	// back to the IP as SNI, which silently authenticates against
	// any cert that happens to include the IP — refuse that
	// combination so a misuse is loud, not silent.
	tcfg, err := spki.PrepareClient(spki.PrepareConfig{
		Base:              c.tlsConfig,
		ServerName:        c.serverName,
		ALPN:              "dot",
		Insecure:          c.insecure,
		SPKIPins:          c.spkiPins,
		ErrInsecureConfig: ErrInsecureTLSConfig,
		ErrServerNameReq:  fmt.Errorf("%w (or *tls.Config.ServerName)", ErrServerNameRequired),
		ErrNoPeerCert:     ErrNoPeerCertificate,
		ErrSPKIMismatch:   ErrSPKIPinMismatch,
	})
	if err != nil {
		return nil, err
	}

	return &Client{addr: addr, timeout: c.timeout, tlsConfig: tcfg, padding: c.padding}, nil
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
