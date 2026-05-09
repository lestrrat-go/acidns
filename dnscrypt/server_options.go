package dnscrypt

import "time"

// ServerOption configures a DNSCrypt [Server].
type ServerOption interface {
	applyDNSCryptServer(*serverConfig)
}

type serverOptionFunc func(*serverConfig)

func (f serverOptionFunc) applyDNSCryptServer(c *serverConfig) { f(c) }

type serverConfig struct {
	bufferSize    int
	maxInflight   int
	writeTimeout  time.Duration
	resolverSK    [32]byte
	resolverSKSet bool
	cert          *Cert
	now           func() time.Time
	clockSkew     time.Duration
	replay        bool
	replayWindow  time.Duration
	replayMax     int
}

// WithCert supplies the signed [Cert] to advertise. Required —
// [NewServer] returns an error if this option is omitted. The cert
// MUST already be signed via [SignCert] before being supplied; the
// server does not re-sign it.
func WithCert(c *Cert) ServerOption {
	return serverOptionFunc(func(cfg *serverConfig) { cfg.cert = c })
}

// WithResolverSecretKey supplies the X25519 32-byte resolver short-term
// private key whose public form is bound into the cert. Required —
// [NewServer] returns an error if this option is omitted or if the
// supplied value is the zero key. The key MUST match the cert's
// ResolverPK; the package cannot verify this binding (signed material
// is opaque) so a mismatch silently produces undecryptable responses.
func WithResolverSecretKey(sk [32]byte) ServerOption {
	return serverOptionFunc(func(c *serverConfig) {
		c.resolverSK = sk
		c.resolverSKSet = true
	})
}

// WithServerBufferSize sets the size of the per-packet read buffer.
// Defaults to 4096 — wide enough to receive an EDNS-extended query
// plus DNSCrypt v2 framing. A non-positive value falls back to the
// default.
func WithServerBufferSize(n int) ServerOption {
	return serverOptionFunc(func(c *serverConfig) {
		if n > 0 {
			c.bufferSize = n
		}
	})
}

// WithServerMaxInflight caps the number of concurrently-running
// handler goroutines. Packets arriving while the cap is reached are
// dropped silently — the kernel UDP receive buffer absorbs short
// bursts and a steady-state-overloaded server returns to baseline
// without unbounded goroutine growth. A non-positive value disables
// the cap. Defaults to 256: each accepted packet performs an X25519
// + ChaCha20-Poly1305 Open, so a higher cap lets a junk-flood
// attacker pin a CPU.
func WithServerMaxInflight(n int) ServerOption {
	return serverOptionFunc(func(c *serverConfig) { c.maxInflight = n })
}

// WithServerClock injects a clock function for cert validity checks
// at Run / Rotate. Defaults to time.Now. Production code should leave
// this unset; tests can pin time to verify boundary behaviour without
// monkey-patching the system clock.
func WithServerClock(now func() time.Time) ServerOption {
	return serverOptionFunc(func(c *serverConfig) { c.now = now })
}

// WithServerClockSkew widens the cert validity-window check by ±d.
// Hourly cert rotation can fail under modest clock drift between the
// server and the cert-signing host: a server with a slightly fast
// clock rejects the cert that just became valid. The default is 5
// seconds; pass 0 to require an exact within-window match. A
// non-zero value tolerates skew at the lower bound (accept "not yet
// valid" up to d in the past) and at the upper bound (accept "just
// expired" up to d in the future) — pick d small enough that an
// attacker cannot replay an expired cert long after revocation.
func WithServerClockSkew(d time.Duration) ServerOption {
	return serverOptionFunc(func(c *serverConfig) { c.clockSkew = d })
}

// WithServerReplayProtection toggles the (clientPK, nonce) replay
// cache. When enabled (the default), each accepted packet is checked
// against a sliding-window cache of recently seen tuples; an exact
// duplicate within the window is dropped without invoking the
// handler. Disable only when the upstream protocol layer already
// guarantees nonce uniqueness or when running stateless-only tests.
func WithServerReplayProtection(v bool) ServerOption {
	return serverOptionFunc(func(c *serverConfig) { c.replay = v })
}

// WithServerReplayWindow sets the sliding window over which a
// (clientPK, nonce) pair is considered a replay. Defaults to 1
// minute, which is wide enough to cover ordinary network re-ordering
// without retaining state for legitimately-distinct queries that
// happen to share a (poorly-chosen) nonce. A non-positive value
// falls back to the default.
func WithServerReplayWindow(d time.Duration) ServerOption {
	return serverOptionFunc(func(c *serverConfig) { c.replayWindow = d })
}

// WithServerReplayCacheMax bounds the in-memory replay cache. Once
// the cache reaches max entries, expired entries are swept; if the
// cache is still full after the sweep, the oldest entries are
// evicted. Defaults to 10,000. A non-positive value falls back to
// the default.
func WithServerReplayCacheMax(n int) ServerOption {
	return serverOptionFunc(func(c *serverConfig) { c.replayMax = n })
}

// WithServerWriteTimeout caps the time the server will spend writing
// a single response datagram. Without a deadline a blocked WriteTo —
// e.g. a saturated socket buffer or a kernel that drops outbound
// traffic for the destination — pins the handler goroutine
// indefinitely; under sustained handshake load the inflight cap
// fills and legitimate packets are dropped. Every other transport
// (UDP/TCP/DoT/DoQ) wires a write deadline; DNSCrypt was the gap.
//
// Defaults to 5 seconds. A non-positive value disables the deadline.
func WithServerWriteTimeout(d time.Duration) ServerOption {
	return serverOptionFunc(func(c *serverConfig) { c.writeTimeout = d })
}
