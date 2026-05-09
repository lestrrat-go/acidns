// Package serverctl is the shared runtime-state primitive for every
// protocol-specific server Controller in acidns: UDP/TCP/DoT/DoH/DoQ/
// DNSCrypt. Every concrete Controller embeds [Core] by value so it
// promotes Addr / Done / Err / Wait without re-declaring them.
//
// Internal-only: the package lives under /internal so sub-packages
// share the implementation without exposing it on the public API
// surface. Add protocol-specific runtime queries (e.g. "current TCP
// connections", "UDP packets dropped at the inflight semaphore") on
// the embedding Controller, not here.
package serverctl

import (
	"net/netip"
	"sync/atomic"
)

// Core is the runtime state shared by every Controller.
type Core struct {
	addr netip.AddrPort
	done chan struct{}
	err  atomic.Pointer[error]
}

// New returns a Core bound to addr with a fresh, unclosed Done channel.
func New(addr netip.AddrPort) Core {
	return Core{addr: addr, done: make(chan struct{})}
}

// Addr returns the address the server is bound to. When the caller
// asked for port 0, this reflects the kernel-assigned ephemeral port.
func (c *Core) Addr() netip.AddrPort { return c.addr }

// Done returns a channel that is closed when the server's work
// goroutine has fully exited (in-flight handlers drained, listening
// socket closed). Wait on this in tests or in process shutdown.
func (c *Core) Done() <-chan struct{} { return c.done }

// Err returns the error that terminated the work goroutine. Returns
// nil before Done is closed and after a clean shutdown via context
// cancellation. Non-nil only when an unexpected condition (e.g. an
// Accept failure outside the recoverable set) ended the loop.
//
// Err does NOT surface Handler panics. The server framework has no
// recover() around handler dispatch (by design); a panicking handler
// propagates up to the listener goroutine and crashes the process
// before the work loop exits. Use a process-level supervisor for
// crash detection.
func (c *Core) Err() error {
	if p := c.err.Load(); p != nil {
		return *p
	}
	return nil
}

// Wait blocks until the server's work goroutine has exited and
// returns its terminal error. Equivalent to <-Done() then Err().
func (c *Core) Wait() error {
	<-c.done
	return c.Err()
}

// SetErr records err as the controller's terminal error. No-op when
// err is nil. Concurrent callers race; the LAST writer wins. The
// loop goroutine should call SetErr at most once and pair it with
// CloseDone shortly after.
func (c *Core) SetErr(err error) {
	if err != nil {
		c.err.Store(&err)
	}
}

// CloseDone closes the Done channel. The loop goroutine must call
// this exactly once on exit; subsequent calls panic.
func (c *Core) CloseDone() { close(c.done) }
