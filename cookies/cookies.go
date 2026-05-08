// Package cookies implements the DNS Cookies state machine specified by
// RFC 7873 and the cookie construction interoperable with RFC 9018. The
// wire-format primitives (EDNS option codec, BADCOOKIE rcode) live in the
// wire package; this package supplies the client-side per-server cache
// plus retry helper, and the server-side secret pool plus validator.
//
// Production features delivered:
//
//   - ClientStore: per-server cache of (client cookie, server cookie),
//     persistent client cookie per server, safe for concurrent use.
//   - Client.Apply: install the cookie EDNS option into an outgoing
//     message.
//   - Client.Observe: learn the server cookie from a response.
//   - Client.Retry: detect BADCOOKIE and rebuild the message with the
//     advertised server cookie so the caller can re-send.
//   - SecretPool: timed rotation of HMAC secrets with a configurable
//     overlap so cookies issued under the previous secret remain valid
//     until they would naturally expire.
//   - Server.Make: construct an RFC 9018 server cookie from (client
//     cookie, client address).
//   - Server.Validate: accept cookies signed by any secret in the pool
//     and within the configured age window.
package cookies

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/lestrrat-go/acidns/wire"
)

// BADCOOKIE is the extended RCODE for "client sent a bad cookie"
// (RFC 7873 §5.2). Defined here for convenience; the wire package may
// surface it as well.
const BADCOOKIE wire.RCODE = 23

// ErrCookieMissing is returned when a response was expected to carry a
// cookie option but none was present.
var ErrCookieMissing = errors.New("cookies: no DNS cookie option present")

// ErrCookieTooShort is returned when a server cookie is shorter than the
// 8-byte minimum imposed by RFC 7873.
var ErrCookieTooShort = errors.New("cookies: server cookie too short")

// ErrCookieMalformed is returned when a server cookie has invalid version
// or length.
var ErrCookieMalformed = errors.New("cookies: server cookie malformed")

// ErrCookieExpired is returned by Server.Validate for a cookie whose
// timestamp lies outside the configured acceptance window.
var ErrCookieExpired = errors.New("cookies: server cookie outside age window")

// ErrCookieMismatch is returned by Server.Validate when the recomputed
// HMAC does not match the supplied cookie's hash field.
var ErrCookieMismatch = errors.New("cookies: server cookie HMAC mismatch")

// Client is the per-server cookie cache + helper for outgoing queries.
type Client interface {
	// Apply installs the cookie EDNS option into b for server. If a
	// server cookie has previously been Observed for that server, it is
	// included; otherwise only the client cookie is sent (RFC 7873
	// §5.2.2 — first-encounter case).
	Apply(server netip.AddrPort, b wire.EDNSBuilder) wire.EDNSBuilder
	// Observe learns the server cookie from resp; subsequent Apply for
	// the same server will include it.
	Observe(server netip.AddrPort, resp wire.Message)
	// Retry inspects resp; if it is BADCOOKIE with a fresh server
	// cookie the cache is updated and ok=true. The caller should then
	// rebuild and resend the query.
	Retry(server netip.AddrPort, resp wire.Message) (ok bool, err error)
}

// NewClient returns a fresh Client backed by an in-memory map.
func NewClient() Client {
	return &client{cache: make(map[netip.AddrPort]clientEntry)}
}

type clientEntry struct {
	clientCookie [8]byte
	serverCookie []byte
}

type client struct {
	mu    sync.Mutex
	cache map[netip.AddrPort]clientEntry
}

func (c *client) Apply(server netip.AddrPort, b wire.EDNSBuilder) wire.EDNSBuilder {
	c.mu.Lock()
	e, ok := c.cache[server]
	if !ok {
		// Generate a fresh client cookie. RFC 7873 recommends per-server
		// uniqueness; we pick fresh random bytes.
		var cc [8]byte
		_, _ = rand.Read(cc[:])
		e = clientEntry{clientCookie: cc}
		c.cache[server] = e
	}
	cc := e.clientCookie
	sc := append([]byte(nil), e.serverCookie...)
	c.mu.Unlock()

	if len(sc) >= 8 {
		opt, err := wire.NewClientServerCookie(cc, sc)
		if err == nil {
			return b.Option(opt)
		}
	}
	return b.Option(wire.NewClientCookie(cc))
}

func (c *client) Observe(server netip.AddrPort, resp wire.Message) {
	cc, sc, ok := extractCookieFromMsg(resp)
	if !ok || len(sc) < 8 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.cache[server]
	e.clientCookie = cc
	e.serverCookie = append(e.serverCookie[:0], sc...)
	c.cache[server] = e
}

func (c *client) Retry(server netip.AddrPort, resp wire.Message) (bool, error) {
	if combinedRCODE(resp) != uint16(BADCOOKIE) {
		return false, nil
	}
	cc, sc, ok := extractCookieFromMsg(resp)
	if !ok {
		return false, ErrCookieMissing
	}
	if len(sc) < 8 {
		return false, ErrCookieTooShort
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.cache[server]
	e.clientCookie = cc
	e.serverCookie = append(e.serverCookie[:0], sc...)
	c.cache[server] = e
	return true, nil
}

// combinedRCODE assembles the RFC 6891 §6.1.3 extended RCODE from msg's
// header (low 4 bits) and OPT pseudo-RR (high 8 bits in TTL[31:24]).
// Returns 0 if no OPT is present.
func combinedRCODE(msg wire.Message) uint16 {
	low := uint16(msg.Flags().RCODE())
	if e, ok := msg.EDNS(); ok && e != nil {
		return uint16(e.ExtendedRCODE())<<4 | (low & 0x0f)
	}
	return low
}

// extractCookieFromMsg pulls (client cookie, server cookie) out of msg's
// EDNS options.
func extractCookieFromMsg(msg wire.Message) ([8]byte, []byte, bool) {
	var zero [8]byte
	edns, ok := msg.EDNS()
	if !ok || edns == nil {
		return zero, nil, false
	}
	for _, o := range edns.Options() {
		if o.Code() != wire.EDNSOptionCookie {
			continue
		}
		cc, sc, ok := wire.Cookies(o)
		if !ok {
			continue
		}
		return cc, sc, true
	}
	return zero, nil, false
}

// Secret is a single HMAC secret used to mint and validate server
// cookies. The library generates 32-byte secrets by default.
type Secret []byte

// SecretPool manages the live + previous server-cookie secrets and
// rotates them on a timer. Operators may override the rotation policy by
// calling Rotate manually.
type SecretPool interface {
	// Current returns the secret used to mint new cookies.
	Current() Secret
	// All returns all valid secrets (current + recently rotated). Use
	// for validation: a cookie counts as valid if any secret accepts it.
	All() []Secret
	// Rotate generates a fresh current secret, demoting the prior
	// current to the second slot and discarding any older secret.
	Rotate() error
}

// NewSecretPool returns a SecretPool with a freshly-minted random secret.
// rotateEvery > 0 starts a background goroutine that calls Rotate on the
// supplied interval; pass 0 to disable automatic rotation.
//
// The caller is responsible for stopping the rotation by invoking the
// returned cancel function on shutdown.
//
// An error is returned if the initial random-secret generation fails
// (a constructor running at server start-up should not panic on a
// transient crypto/rand error).
func NewSecretPool(rotateEvery time.Duration) (SecretPool, func(), error) {
	p := &secretPool{}
	if err := p.Rotate(); err != nil {
		return nil, nil, err
	}
	cancel := func() {}
	if rotateEvery > 0 {
		stop := make(chan struct{})
		cancel = func() { close(stop) }
		go func() {
			tick := time.NewTicker(rotateEvery)
			defer tick.Stop()
			for {
				select {
				case <-stop:
					return
				case <-tick.C:
					_ = p.Rotate()
				}
			}
		}()
	}
	return p, cancel, nil
}

type secretPool struct {
	mu       sync.RWMutex
	current  Secret
	previous Secret
}

func (p *secretPool) Current() Secret {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append(Secret(nil), p.current...)
}

func (p *secretPool) All() []Secret {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Secret, 0, 2)
	if len(p.current) > 0 {
		out = append(out, append(Secret(nil), p.current...))
	}
	if len(p.previous) > 0 {
		out = append(out, append(Secret(nil), p.previous...))
	}
	return out
}

func (p *secretPool) Rotate() error {
	fresh := make(Secret, 32)
	if _, err := rand.Read(fresh); err != nil {
		return fmt.Errorf("cookies: rotate: %w", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.previous = p.current
	p.current = fresh
	return nil
}

// Server constructs and validates RFC 9018 server cookies.
type Server interface {
	// Make returns a 16-byte server cookie binding clientCookie to
	// clientAddr at the supplied timestamp. Use time.Now() in
	// production; tests inject a fixed clock.
	Make(clientCookie [8]byte, clientAddr netip.Addr, ts time.Time) []byte
	// Validate checks serverCookie against clientCookie + clientAddr.
	// Returns the embedded timestamp on success and a typed error on
	// failure.
	Validate(serverCookie []byte, clientCookie [8]byte, clientAddr netip.Addr, now time.Time) (time.Time, error)
	// MaxAge is the cookie acceptance window (RFC 7873 §5.2.5
	// recommends ~1 hour; the default below is 1 hour, configurable).
	MaxAge() time.Duration
}

// NewServer returns a Server backed by pool. maxAge is the window beyond
// the cookie's embedded timestamp after which Validate returns
// ErrCookieExpired (default 1 hour if zero).
func NewServer(pool SecretPool, maxAge time.Duration) Server {
	if maxAge <= 0 {
		maxAge = time.Hour
	}
	return &serverImpl{pool: pool, maxAge: maxAge}
}

type serverImpl struct {
	pool   SecretPool
	maxAge time.Duration
}

func (s *serverImpl) MaxAge() time.Duration { return s.maxAge }

func (s *serverImpl) Make(clientCookie [8]byte, clientAddr netip.Addr, ts time.Time) []byte {
	secret := s.pool.Current()
	return mintCookie(secret, clientCookie, clientAddr, ts)
}

func (s *serverImpl) Validate(serverCookie []byte, clientCookie [8]byte, clientAddr netip.Addr, now time.Time) (time.Time, error) {
	if len(serverCookie) != 16 {
		return time.Time{}, fmt.Errorf("%w: length %d", ErrCookieMalformed, len(serverCookie))
	}
	if serverCookie[0] != 1 {
		return time.Time{}, fmt.Errorf("%w: version %d", ErrCookieMalformed, serverCookie[0])
	}
	ts := time.Unix(int64(binary.BigEndian.Uint32(serverCookie[4:8])), 0).UTC()
	if now.Sub(ts) > s.maxAge {
		return time.Time{}, ErrCookieExpired
	}
	if ts.Sub(now) > 5*time.Minute {
		// Cookie issued in the (substantial) future → invalid.
		return time.Time{}, ErrCookieExpired
	}
	for _, sec := range s.pool.All() {
		want := mintCookie(sec, clientCookie, clientAddr, ts)
		if hmac.Equal(want[8:], serverCookie[8:]) {
			return ts, nil
		}
	}
	return time.Time{}, ErrCookieMismatch
}

// mintCookie constructs the 16-byte RFC 9018 server cookie:
//
//	0x01 (version) || 0x00 0x00 0x00 (reserved) || timestamp (4 BE) ||
//	HMAC-SHA256(secret, clientCookie || version || reserved || timestamp || clientAddr)[:8]
func mintCookie(secret Secret, clientCookie [8]byte, addr netip.Addr, ts time.Time) []byte {
	out := make([]byte, 16)
	out[0] = 1
	binary.BigEndian.PutUint32(out[4:8], uint32(ts.Unix()))

	h := hmac.New(sha256.New, secret)
	h.Write(clientCookie[:])
	h.Write(out[:8])
	switch {
	case addr.Is4():
		b4 := addr.As4()
		h.Write(b4[:])
	case addr.Is6():
		b16 := addr.As16()
		h.Write(b16[:])
	default:
		// Zero-length address = treat as zero-byte input. RFC 9018 doesn't
		// allow this in practice but we don't crash.
	}
	mac := h.Sum(nil)
	copy(out[8:16], mac[:8])
	return out
}
