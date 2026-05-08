package dnscrypt

// ServerOption configures a DNSCrypt [Server].
type ServerOption interface {
	applyDNSCryptServer(*serverConfig)
}

type serverOptionFunc func(*serverConfig)

func (f serverOptionFunc) applyDNSCryptServer(c *serverConfig) { f(c) }

type serverConfig struct {
	bufferSize  int
	maxInflight int
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
// the cap. Defaults to 4096.
func WithServerMaxInflight(n int) ServerOption {
	return serverOptionFunc(func(c *serverConfig) { c.maxInflight = n })
}
