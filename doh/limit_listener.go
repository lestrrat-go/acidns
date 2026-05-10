package doh

import (
	"net"
	"net/netip"
	"sync"
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

	sem          chan struct{}
	once         sync.Once
	done         chan struct{}
	maxPerSource int

	perSourceMu sync.Mutex
	perSource   map[netip.Addr]int
}

func newLimitListener(l net.Listener, n, perSource int) *limitListener {
	return &limitListener{
		Listener:     l,
		sem:          make(chan struct{}, n),
		done:         make(chan struct{}),
		maxPerSource: perSource,
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

// reservePerSource increments the per-source counter if the cap
// permits and returns true. addr is the unmapped remote address.
func (l *limitListener) reservePerSource(addr netip.Addr) bool {
	if l.maxPerSource <= 0 {
		return true
	}
	l.perSourceMu.Lock()
	defer l.perSourceMu.Unlock()
	if l.perSource[addr] >= l.maxPerSource {
		return false
	}
	if l.perSource == nil {
		l.perSource = make(map[netip.Addr]int)
	}
	l.perSource[addr]++
	return true
}

func (l *limitListener) releasePerSource(addr netip.Addr) {
	if l.maxPerSource <= 0 {
		return
	}
	l.perSourceMu.Lock()
	defer l.perSourceMu.Unlock()
	if l.perSource[addr] <= 1 {
		delete(l.perSource, addr)
		return
	}
	l.perSource[addr]--
}

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
		if l.maxPerSource <= 0 {
			return &limitConn{Conn: c, release: l.release}, nil
		}
		addr, ok := remoteUnmappedAddr(c)
		if !ok {
			// Cannot identify source — admit the connection and
			// rely solely on the global cap.
			return &limitConn{Conn: c, release: l.release}, nil
		}
		if !l.reservePerSource(addr) {
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
			srcDec:  l.releasePerSource,
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
