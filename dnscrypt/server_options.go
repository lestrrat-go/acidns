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
