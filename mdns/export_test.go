package mdns

import "net"

// SetOpenConn replaces the package-level connection opener used by
// Browse. It returns a function that restores the original opener.
// Test-only seam: real multicast cannot be bound reliably in CI.
func SetOpenConn(f func() (net.PacketConn, error)) func() {
	prev := openConn
	openConn = f
	return func() { openConn = prev }
}
