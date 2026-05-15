package mdns_test

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/mdns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/stretchr/testify/require"
)

// TestLocalDomain pins the ".local" suffix exposed by LocalDomain, the
// canonical accessor library consumers use when filtering or rebuilding
// mDNS-owned names.
func TestLocalDomain(t *testing.T) {
	t.Parallel()
	require.Equal(t, wire.MustParseName("local"), mdns.LocalDomain())
}

// TestServiceAccessorsMirrorBuilder exercises the SRV-shape accessors
// (Priority / Weight / TTL) by round-tripping them through ServiceBuilder.
// These accessors mirror the builder setters and are the public surface
// consumers use to read a discovered Service value.
func TestServiceAccessorsMirrorBuilder(t *testing.T) {
	t.Parallel()
	s := mdns.NewServiceBuilder().
		Instance("Foo Bar").
		Type(wire.MustParseName("_http._tcp.local")).
		Host(wire.MustParseName("foo.local")).
		Port(8080).
		Priority(7).
		Weight(13).
		Addrs([]netip.Addr{netip.MustParseAddr("203.0.113.1")}).
		Text(map[string]string{"path": "/"}).
		TTL(90 * time.Second).
		Build()

	require.Equal(t, uint16(7), s.Priority())
	require.Equal(t, uint16(13), s.Weight())
	require.Equal(t, 90*time.Second, s.TTL())
}

// TestBrowseWithMulticastInterface exercises WithMulticastInterface. The
// option is a no-op when WithBrowseConn pre-empts the listener factory;
// here we pair them so the test does not actually bind a multicast group.
func TestBrowseWithMulticastInterface(t *testing.T) {
	t.Parallel()
	open := func() (net.PacketConn, error) {
		return net.ListenPacket("udp4", "127.0.0.1:0")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, _ = mdns.Browse(ctx, "_http._tcp",
		mdns.WithBrowseConn(open),
		mdns.WithMulticastInterface(nil),
	)
}

// TestPublicationBuilderTextMap exercises PublicationBuilder.TextMap, the
// bulk-merge variant of the per-pair Text setter.
func TestPublicationBuilderTextMap(t *testing.T) {
	t.Parallel()
	p, err := mdns.NewPublicationBuilder().
		Instance(wire.MustParseName("Foo Bar._http._tcp.local.")).
		Type(wire.MustParseName("_http._tcp.local.")).
		Host(wire.MustParseName("foo.local.")).
		Port(8080).
		Addrs(netip.MustParseAddr("203.0.113.1")).
		TextMap(map[string]string{"path": "/", "version": "2"}).
		TTL(120 * time.Second).
		Build()
	require.NoError(t, err)
	require.NotNil(t, p)
}
