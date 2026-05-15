package doh

import (
	"net"
	"net/netip"
	"sync"

	"github.com/lestrrat-go/acidns/internal/netutil"
)

// limitListener wraps a net.Listener and bounds the number of
// concurrently-open accepted connections via a counting semaphore.
// Excess connections wait in the kernel's listen backlog and are
// accepted as slots free up. With a non-zero per-source cap, a
// single client IP cannot occupy more than maxPerSource slots; over-
// budget connections are silently dropped and the accept loop
// continues (returning an error would stop http.Server's loop).
//
// Mirrors golang.org/x/net/netutil LimitListener with the per-source
// extension; reimplemented here to avoid promoting that import from
// indirect to direct.
type limitListener struct {
	net.Listener

	sem  chan struct{}
	once sync.Once
	done chan struct{}
	src  *netutil.SourceLimiter
}

func newLimitListener(l net.Listener, n, perSource int) *limitListener {
	return &limitListener{
		Listener: l,
		sem:      make(chan struct{}, n),
		done:     make(chan struct{}),
		src:      netutil.NewSourceLimiter(perSource),
	}
}

func (l *limitListener) acquire() bool {
	select {
	case <-l.done:
		return false
	case l.sem <- struct{}{}:
		return true
	}
}

func (l *limitListener) release() { <-l.sem }

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		if !l.acquire() {
			return nil, net.ErrClosed
		}
		c, err := l.Listener.Accept()
		if err != nil {
			l.release()
			return nil, err
		}
		addr, ok := remoteUnmappedAddr(c)
		if !ok {
			// Cannot identify source — admit the connection and
			// rely solely on the global cap. (Skips per-source
			// bookkeeping; the SourceLimiter would otherwise key on
			// the zero Addr.)
			return &limitConn{Conn: c, release: l.release}, nil
		}
		if !l.src.Reserve(addr) {
			// Silent drop: returning an error here would stop the
			// http.Server's accept loop. Free the global slot and
			// continue accepting.
			_ = c.Close()
			l.release()
			continue
		}
		return &limitConn{
			Conn:    c,
			release: l.release,
			srcAddr: addr,
			srcDec:  l.src.Release,
		}, nil
	}
}

func (l *limitListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

// remoteUnmappedAddr extracts the unmapped peer address from c. v4-
// mapped IPv6 addresses are folded into their v4 form so the per-
// source map keys consistently regardless of dual-stack listener mode.
func remoteUnmappedAddr(c net.Conn) (netip.Addr, bool) {
	tcp, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	a, ok := netip.AddrFromSlice(tcp.IP)
	if !ok {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

type limitConn struct {
	net.Conn

	once    sync.Once
	release func()
	srcAddr netip.Addr
	srcDec  func(netip.Addr)
}

func (c *limitConn) Close() error {
	c.once.Do(func() {
		c.release()
		if c.srcDec != nil {
			c.srcDec(c.srcAddr)
		}
	})
	return c.Conn.Close()
}
