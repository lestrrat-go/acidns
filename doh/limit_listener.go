package doh

import (
	"net"
	"sync"
)

// limitListener wraps a net.Listener and bounds the number of
// concurrently-open accepted connections via a counting semaphore.
// Excess connections wait in the kernel's listen backlog and are
// accepted as slots free up. Mirrors golang.org/x/net/netutil
// LimitListener; reimplemented here to avoid promoting that import
// from indirect to direct.
type limitListener struct {
	net.Listener
	sem  chan struct{}
	once sync.Once
	done chan struct{}
}

func newLimitListener(l net.Listener, n int) *limitListener {
	return &limitListener{
		Listener: l,
		sem:      make(chan struct{}, n),
		done:     make(chan struct{}),
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
	if !l.acquire() {
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		l.release()
		return nil, err
	}
	return &limitConn{Conn: c, release: l.release}, nil
}

func (l *limitListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}
