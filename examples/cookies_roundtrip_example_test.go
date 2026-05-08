package examples_test

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns/cookies"
	"github.com/lestrrat-go/acidns/wire"
)

func Example_cookies_roundtrip() {
	// Server side: a SecretPool drives the HMAC key for RFC 9018 server
	// cookies. Pass 0 to disable automatic rotation in this example.
	pool, cancel := cookies.NewSecretPool(0)
	defer cancel()
	srv := cookies.NewServer(pool, time.Hour)

	clientCookie := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	clientAddr := netip.MustParseAddr("203.0.113.1")
	now := time.Unix(1_700_000_000, 0).UTC()

	// Mint a server cookie. Validate accepts it.
	cookie := srv.Make(clientCookie, clientAddr, now)
	fmt.Println("server cookie length:", len(cookie))
	fmt.Println("version byte:", cookie[0])

	if _, err := srv.Validate(cookie, clientCookie, clientAddr, now); err == nil {
		fmt.Println("validate same client: ok")
	}

	// A different source address must not validate (RFC 9018 §3): the
	// HMAC binds the cookie to the originating address.
	other := netip.MustParseAddr("203.0.113.2")
	if _, err := srv.Validate(cookie, clientCookie, other, now); errors.Is(err, cookies.ErrCookieMismatch) {
		fmt.Println("validate different client: mismatch (expected)")
	}

	// Outside the acceptance window: ErrCookieExpired.
	if _, err := srv.Validate(cookie, clientCookie, clientAddr, now.Add(2*time.Hour)); errors.Is(err, cookies.ErrCookieExpired) {
		fmt.Println("validate after window: expired (expected)")
	}

	// Client side: Apply installs a cookie EDNS option on outgoing
	// queries. The first call emits a client-only cookie; we just check
	// that the option is present (its bytes are random by design).
	c := cookies.NewClient()
	server := netip.MustParseAddrPort("198.51.100.10:53")
	b := wire.NewEDNSBuilder()
	b = c.Apply(server, b)
	edns := b.Build()
	for _, o := range edns.Options() {
		if o.Code() == wire.EDNSOptionCookie {
			fmt.Println("client emitted cookie option")
			break
		}
	}

	// OUTPUT:
	// server cookie length: 16
	// version byte: 1
	// validate same client: ok
	// validate different client: mismatch (expected)
	// validate after window: expired (expected)
	// client emitted cookie option
}
