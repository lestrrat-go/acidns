// Package netutil hosts small networking primitives shared by the
// acidns transport servers (TCP, DoT, DoH). The helpers here are
// transport-agnostic — they deal in net.Conn, net.Listener, and
// netip.AddrPort — and exist purely to avoid duplicating identical
// accept-loop, source-limiting, and remote-address bookkeeping across
// the protocol packages.
//
// Internal-only: the package lives under /internal so sub-packages
// share the implementation without exposing it on the public API
// surface.
package netutil

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
)

// AcceptBackoffInitial and AcceptBackoffCap bound the exponential backoff
// applied between transient Accept failures (EMFILE/ENFILE/EAGAIN/...).
// The first failure waits AcceptBackoffInitial; each subsequent consecutive
// failure doubles the wait, capped at AcceptBackoffCap. The window is
// reset to zero on the first success.
const (
	AcceptBackoffInitial = 5 * time.Millisecond
	AcceptBackoffCap     = time.Second
)

// IsAcceptTransient reports whether err is a transient Accept failure
// that should not terminate the serve loop. Uses errors.Is on the
// kernel-resource exhaustion modes so we don't rely on locale-
// dependent error string substrings.
func IsAcceptTransient(err error) bool {
	if err == nil {
		return false
	}
	for _, target := range []syscall.Errno{
		syscall.EMFILE,
		syscall.ENFILE,
		syscall.EAGAIN,
		syscall.ENOBUFS,
		syscall.ENOMEM,
	} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// RemoteAddrPort returns the connection's remote address as a
// netip.AddrPort. We prefer net.TCPAddr.AddrPort() over re-parsing the
// String() form because the latter silently returns the zero AddrPort
// on unexpected formats, which would let per-source policies (ACL,
// rate limit) bucket all such peers together.
func RemoteAddrPort(c net.Conn) netip.AddrPort {
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return ta.AddrPort()
	}
	ap, _ := netip.ParseAddrPort(c.RemoteAddr().String())
	return ap
}

// SourceLimiter caps the number of concurrently-open resources
// (connections, sessions) attributed to a single remote IP. The zero
// value is a no-op; construct one with [NewSourceLimiter] to enforce a
// non-zero cap.
//
// Bucketing is on netip.Addr.Unmap so a v4-mapped IPv6 client shares a
// bucket with its v4 form (consistent regardless of dual-stack listener
// mode). Entries are removed when their count reaches zero so the
// internal map does not grow without bound across the lifetime of the
// limiter.
type SourceLimiter struct {
	max int

	mu     sync.Mutex
	counts map[netip.Addr]int
}

// NewSourceLimiter returns a SourceLimiter that admits at most maxPerSource
// concurrent reservations per source address. A non-positive maxPerSource
// disables the cap entirely: Reserve always succeeds and Release is a
// no-op.
func NewSourceLimiter(maxPerSource int) *SourceLimiter {
	return &SourceLimiter{max: maxPerSource}
}

// Reserve increments the per-source counter for addr if the cap
// permits, returning true. When the cap would be exceeded it returns
// false and the caller must NOT call Release. addr is canonicalised
// via Unmap.
func (l *SourceLimiter) Reserve(addr netip.Addr) bool {
	if l == nil || l.max <= 0 {
		return true
	}
	addr = addr.Unmap()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts[addr] >= l.max {
		return false
	}
	if l.counts == nil {
		l.counts = make(map[netip.Addr]int)
	}
	l.counts[addr]++
	return true
}

// Release decrements the per-source counter for addr. Paired with a
// successful Reserve. addr is canonicalised via Unmap. Releasing an
// address with a zero count is silently ignored — the limiter never
// goes negative.
func (l *SourceLimiter) Release(addr netip.Addr) {
	if l == nil || l.max <= 0 {
		return
	}
	addr = addr.Unmap()
	l.mu.Lock()
	defer l.mu.Unlock()
	c := l.counts[addr]
	if c <= 1 {
		delete(l.counts, addr)
		return
	}
	l.counts[addr] = c - 1
}
