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
	"log"
	"net/netip"
	"sync"
	"sync/atomic"
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
	Apply(server netip.AddrPort, b *wire.EDNSBuilder) *wire.EDNSBuilder
	// Observe learns the server cookie from resp; subsequent Apply for
	// the same server will include it.
	Observe(server netip.AddrPort, resp wire.Message)
	// Retry inspects resp; if it is BADCOOKIE with a fresh server
	// cookie the cache is updated and ok=true. The caller should then
	// rebuild and resend the query.
	Retry(server netip.AddrPort, resp wire.Message) (ok bool, err error)
	// RNGFailures returns the cumulative number of times Apply could
	// not draw fresh entropy for a client cookie and fell back to
	// emitting the query without a cookie option. A non-zero value is
	// a strong signal the host's CSPRNG is wedged (entropy starvation
	// on a freshly-booted VM, broken kernel RNG, etc.); operators
	// should alert on it.
	RNGFailures() uint64
}

// DefaultClientMaxEntries caps the number of distinct servers a Client
// remembers cookies for. A long-running recursive resolver talks to
// every authoritative server it ever asks; without a cap the cache
// grows unbounded as the resolver visits more authoritatives. 8192
// is comfortably above any healthy resolver's working set while
// bounding worst-case memory.
const DefaultClientMaxEntries = 8192

// ClientOption configures a [Client] returned by [NewClient].
type ClientOption interface{ applyClient(*clientConfig) }

type clientOptionFunc func(*clientConfig)

func (f clientOptionFunc) applyClient(c *clientConfig) { f(c) }

type clientConfig struct {
	maxEntries int
	now        func() time.Time
}

// WithClientMaxEntries caps the number of (server, cookie) tuples
// kept in memory. When the cap is reached the oldest-touched entry
// is evicted before a new one is inserted. A non-positive value
// disables the cap. Defaults to [DefaultClientMaxEntries].
func WithClientMaxEntries(n int) ClientOption {
	return clientOptionFunc(func(c *clientConfig) { c.maxEntries = n })
}

// WithClientClock injects a custom clock for the LRU eviction
// timestamps. Intended for tests; production callers should leave
// the default.
func WithClientClock(now func() time.Time) ClientOption {
	return clientOptionFunc(func(c *clientConfig) { c.now = now })
}

// NewClient returns a fresh Client backed by an in-memory map.
func NewClient(opts ...ClientOption) (Client, error) {
	cfg := clientConfig{maxEntries: DefaultClientMaxEntries, now: time.Now}
	for _, o := range opts {
		o.applyClient(&cfg)
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	return &client{
		cache:      make(map[netip.AddrPort]clientEntry),
		maxEntries: cfg.maxEntries,
		now:        cfg.now,
	}, nil
}

type clientEntry struct {
	clientCookie [8]byte
	serverCookie []byte
	updated      time.Time
}

type client struct {
	mu          sync.Mutex
	cache       map[netip.AddrPort]clientEntry
	maxEntries  int
	now         func() time.Time
	rngFailures atomic.Uint64
	rngLogged   atomic.Bool
}

func (c *client) RNGFailures() uint64 { return c.rngFailures.Load() }

func (c *client) Apply(server netip.AddrPort, b *wire.EDNSBuilder) *wire.EDNSBuilder {
	c.mu.Lock()
	now := c.now()
	e, ok := c.cache[server]
	if !ok {
		// Generate a fresh client cookie. RFC 7873 recommends per-server
		// uniqueness; we pick fresh random bytes from crypto/rand.
		var cc [8]byte
		if _, err := rand.Read(cc[:]); err != nil {
			// Fail closed: emit the query without a cookie option rather
			// than shipping an all-zero client cookie. The server-cookie
			// binding (RFC 9018 §3) treats client cookie as input to the
			// HMAC; an all-zero value would let many failing-RNG clients
			// share a cookie identity with each other.
			c.mu.Unlock()
			c.rngFailures.Add(1)
			if c.rngLogged.CompareAndSwap(false, true) {
				log.Printf("cookies: rand.Read failed: %v; falling back to cookieless queries (further RNG failures will be silent — see Client.RNGFailures())", err)
			}
			return b
		}
		if c.maxEntries > 0 && len(c.cache) >= c.maxEntries {
			c.evictLocked()
		}
		e = clientEntry{clientCookie: cc, updated: now}
	} else {
		e.updated = now
	}
	c.cache[server] = e
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
	e, exists := c.cache[server]
	if !exists && c.maxEntries > 0 && len(c.cache) >= c.maxEntries {
		c.evictLocked()
	}
	e.clientCookie = cc
	e.serverCookie = append(e.serverCookie[:0], sc...)
	e.updated = c.now()
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
	e, exists := c.cache[server]
	if !exists && c.maxEntries > 0 && len(c.cache) >= c.maxEntries {
		c.evictLocked()
	}
	e.clientCookie = cc
	e.serverCookie = append(e.serverCookie[:0], sc...)
	e.updated = c.now()
	c.cache[server] = e
	return true, nil
}

// evictLocked drops the single oldest-updated entry. Caller holds
// c.mu. The cache holds at most one entry per upstream
// [netip.AddrPort] so a single eviction is sufficient — at the next
// insertion a fresh client cookie will be re-minted on demand if
// the evicted server is contacted again.
func (c *client) evictLocked() {
	var oldestKey netip.AddrPort
	var oldestTime time.Time
	first := true
	for k, e := range c.cache {
		if first || e.updated.Before(oldestTime) {
			oldestKey = k
			oldestTime = e.updated
			first = false
		}
	}
	if !first {
		delete(c.cache, oldestKey)
	}
}

// combinedRCODE assembles the RFC 6891 §6.1.3 extended RCODE from msg's
// header (low 4 bits) and OPT pseudo-RR (high 8 bits in TTL[31:24]).
// Returns 0 if no OPT is present.
func combinedRCODE(msg wire.Message) uint16 {
	low := uint16(msg.Flags().RCODE())
	if e, ok := msg.EDNS(); ok {
		return uint16(e.ExtendedRCODE())<<4 | (low & 0x0f)
	}
	return low
}

// extractCookieFromMsg pulls (client cookie, server cookie) out of msg's
// EDNS options.
func extractCookieFromMsg(msg wire.Message) ([8]byte, []byte, bool) {
	var zero [8]byte
	edns, ok := msg.EDNS()
	if !ok {
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

// SecretPool manages the live + previous server-cookie secrets. The
// concrete pool returned by [NewSecretPool] additionally exposes a
// Rotate method for tests and admin tooling, but the SecretPool
// interface intentionally omits it: a misbehaving caller holding the
// pool could otherwise force an out-of-cycle rotation and instantly
// invalidate every in-flight client cookie.
type SecretPool interface {
	// Current returns the secret used to mint new cookies.
	Current() Secret
	// All returns all valid secrets (current + recently rotated). Use
	// for validation: a cookie counts as valid if any secret accepts it.
	All() []Secret
	// Close stops the rotation goroutine if [WithPoolRotateEvery] was
	// supplied. Safe to call when no rotation goroutine is running
	// and idempotent on repeated calls.
	Close()
}

// PoolOption configures a [SecretPool] returned by [NewSecretPool].
type PoolOption interface{ applyPool(*poolConfig) }

type poolOptionFunc func(*poolConfig)

func (f poolOptionFunc) applyPool(c *poolConfig) { f(c) }

type poolConfig struct {
	rotateEvery time.Duration
}

// WithPoolRotateEvery enables automatic rotation of the pool's
// HMAC secret on the supplied interval. With auto-rotation enabled
// the returned pool's [SecretPool.Close] must be called on shutdown
// to stop the rotation goroutine. A non-positive value disables
// automatic rotation.
func WithPoolRotateEvery(d time.Duration) PoolOption {
	return poolOptionFunc(func(c *poolConfig) { c.rotateEvery = d })
}

// NewSecretPool returns a [MemorySecretPool] with a freshly-minted
// random secret. With [WithPoolRotateEvery] the pool spawns a
// background goroutine that periodically rotates the current secret;
// the goroutine is shut down by [MemorySecretPool.Close]. An error is
// returned if the initial random-secret generation fails.
//
// The returned concrete type satisfies [SecretPool] and additionally
// exposes Rotate for tests and admin tooling. Callers that store the
// pool as a SecretPool interface lose the Rotate method by design —
// see the [SecretPool] doc.
func NewSecretPool(opts ...PoolOption) (*MemorySecretPool, error) {
	cfg := poolConfig{}
	for _, o := range opts {
		o.applyPool(&cfg)
	}
	p := &MemorySecretPool{}
	if err := p.Rotate(); err != nil {
		return nil, err
	}
	if cfg.rotateEvery > 0 {
		p.stop = make(chan struct{})
		go func() {
			tick := time.NewTicker(cfg.rotateEvery)
			defer tick.Stop()
			for {
				select {
				case <-p.stop:
					return
				case <-tick.C:
					_ = p.Rotate()
				}
			}
		}()
	}
	return p, nil
}

// MemorySecretPool is the in-process [SecretPool] implementation.
// Construct via [NewSecretPool].
type MemorySecretPool struct {
	mu       sync.RWMutex
	current  Secret
	previous Secret
	stop     chan struct{}
	stopOnce sync.Once
}

func (p *MemorySecretPool) Close() {
	if p.stop == nil {
		return
	}
	p.stopOnce.Do(func() { close(p.stop) })
}

func (p *MemorySecretPool) Current() Secret {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append(Secret(nil), p.current...)
}

func (p *MemorySecretPool) All() []Secret {
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

func (p *MemorySecretPool) Rotate() error {
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

// DefaultMaxFutureSkew is the future-skew tolerance applied by the
// default Server. Clocks across hosts diverge by seconds in practice;
// 5 minutes is a generous bound that still rejects cookies issued
// hours into the future.
const DefaultMaxFutureSkew = 5 * time.Minute

// ServerOption configures the [Server] returned by [NewServer].
type ServerOption interface{ applyCookieServer(*serverConfig) }

type serverOptionFunc func(*serverConfig)

func (f serverOptionFunc) applyCookieServer(c *serverConfig) { f(c) }

type serverConfig struct {
	maxAge        time.Duration
	maxFutureSkew time.Duration
}

// WithServerMaxAge sets the cookie acceptance window. RFC 7873 §5.2.5
// recommends ~1 hour; that is the default if this option is not set.
func WithServerMaxAge(d time.Duration) ServerOption {
	return serverOptionFunc(func(c *serverConfig) {
		if d > 0 {
			c.maxAge = d
		}
	})
}

// WithMaxFutureSkew sets how far in the future a cookie's embedded
// timestamp may be before Validate returns ErrCookieExpired. Operators
// who want stricter clock alignment can pass a smaller value (e.g.
// 30 s); pass 0 to keep the default of [DefaultMaxFutureSkew].
func WithMaxFutureSkew(d time.Duration) ServerOption {
	return serverOptionFunc(func(c *serverConfig) {
		if d > 0 {
			c.maxFutureSkew = d
		}
	})
}

// NewServer returns a [Server] backed by pool. By default the cookie
// acceptance window is 1 hour and the future-skew tolerance is
// [DefaultMaxFutureSkew]; pass [WithServerMaxAge] / [WithMaxFutureSkew]
// to override.
func NewServer(pool SecretPool, opts ...ServerOption) (Server, error) {
	cfg := serverConfig{maxAge: time.Hour, maxFutureSkew: DefaultMaxFutureSkew}
	for _, o := range opts {
		o.applyCookieServer(&cfg)
	}
	return &serverImpl{pool: pool, maxAge: cfg.maxAge, maxFutureSkew: cfg.maxFutureSkew}, nil
}

type serverImpl struct {
	pool          SecretPool
	maxAge        time.Duration
	maxFutureSkew time.Duration
}

func (s *serverImpl) MaxAge() time.Duration { return s.maxAge }

func (s *serverImpl) Make(clientCookie [8]byte, clientAddr netip.Addr, ts time.Time) []byte {
	secret := s.pool.Current()
	return mintCookie(secret, clientCookie, clientAddr.Unmap(), ts)
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
	if ts.Sub(now) > s.maxFutureSkew {
		// Cookie issued in the (substantial) future → invalid.
		return time.Time{}, ErrCookieExpired
	}
	// Canonicalise v4-mapped IPv6 ("::ffff:1.2.3.4") to plain IPv4
	// before binding so a client that reconnects via the un-mapped
	// form still validates the cookie minted under the mapped form
	// (and vice versa).
	addr := clientAddr.Unmap()
	for _, sec := range s.pool.All() {
		want := mintCookie(sec, clientCookie, addr, ts)
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
