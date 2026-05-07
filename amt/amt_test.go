package amt_test

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/amt"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
	"github.com/stretchr/testify/require"
)

// fakeAnswer is a minimal acidns.Answer implementation that exposes a
// canned record list.
type fakeAnswer struct{ records []wire.Record }

func (f *fakeAnswer) Question() wire.Question { return nil }
func (f *fakeAnswer) Records() []wire.Record  { return f.records }
func (f *fakeAnswer) Raw() wire.Message       { return nil }
func (f *fakeAnswer) RCODE() wire.RCODE       { return wire.RCODENoError }
func (f *fakeAnswer) Authoritative() bool     { return false }
func (f *fakeAnswer) Truncated() bool         { return false }

// fakeResolver returns either a canned answer or an error.
type fakeResolver struct {
	records []wire.Record
	err     error
}

func (f *fakeResolver) Resolve(_ context.Context, _ wire.Name, _ rrtype.Type) (acidns.Answer, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &fakeAnswer{records: f.records}, nil
}

// mismatchRecord pretends to be a SRV-typed record while carrying an
// rdata payload that is NOT rdata.SRV. This lets us exercise the type
// assertion miss inside Discover.
type mismatchRecord struct {
	name wirebb.Name
	rd   rdata.RData
}

func (r mismatchRecord) Name() wirebb.Name   { return r.name }
func (r mismatchRecord) Type() rrtype.Type   { return rrtype.SRV }
func (r mismatchRecord) Class() rrtype.Class { return rrtype.ClassIN }
func (r mismatchRecord) TTL() time.Duration  { return time.Minute }
func (r mismatchRecord) RData() rdata.RData  { return r.rd }

func TestDiscoveryName(t *testing.T) {
	t.Parallel()
	t.Run("happy path", func(t *testing.T) {
		t.Parallel()
		n, err := amt.DiscoveryName(wire.MustParseName("example.com"))
		require.NoError(t, err)
		require.Equal(t, "_amt._udp.example.com.", n.String())
	})

	t.Run("name overflow returns error", func(t *testing.T) {
		t.Parallel()
		// Three 63-octet labels + a 60-octet label is a valid 254-byte
		// wire name. Prepending `_amt._udp.` (10 wire bytes) pushes the
		// result past the 255-byte limit and forces ParseName to fail.
		l63 := strings.Repeat("a", 63)
		l60 := strings.Repeat("b", 60)
		long, err := wire.ParseName(l63 + "." + l63 + "." + l63 + "." + l60)
		require.NoError(t, err)
		_, err = amt.DiscoveryName(long)
		require.Error(t, err)
	})
}

func TestDiscover_Sorting(t *testing.T) {
	t.Parallel()
	r := &fakeResolver{
		records: []wire.Record{
			wire.NewRecord(wire.MustParseName("_amt._udp.example.com"), 60*time.Second,
				rdata.NewSRV(20, 0, 2268, wire.MustParseName("relay-b.example.com"))),
			wire.NewRecord(wire.MustParseName("_amt._udp.example.com"), 60*time.Second,
				rdata.NewSRV(10, 0, 2268, wire.MustParseName("relay-a.example.com"))),
			wire.NewRecord(wire.MustParseName("_amt._udp.example.com"), 60*time.Second,
				rdata.NewSRV(10, 50, 2268, wire.MustParseName("relay-c.example.com"))),
		},
	}
	relays, err := amt.Discover(t.Context(), r, wire.MustParseName("example.com"))
	require.NoError(t, err)
	require.Len(t, relays, 3)
	require.Equal(t, uint16(10), relays[0].Priority)
	require.Equal(t, uint16(10), relays[1].Priority)
	require.Equal(t, uint16(20), relays[2].Priority)
	// Stable sort: weight ties preserve server-supplied order, so
	// relay-a (weight 0) comes before relay-c (weight 50).
	require.Equal(t, "relay-a.example.com.", relays[0].Target.String())
	require.Equal(t, "relay-c.example.com.", relays[1].Target.String())
	require.Equal(t, "relay-b.example.com.", relays[2].Target.String())
	require.Equal(t, uint16(2268), relays[0].Port)
	require.Equal(t, uint16(0), relays[0].Weight)
}

func TestDiscover_NoRecords(t *testing.T) {
	t.Parallel()
	r := &fakeResolver{}
	relays, err := amt.Discover(t.Context(), r, wire.MustParseName("example.com"))
	require.NoError(t, err)
	require.Empty(t, relays)
}

func TestDiscover_FiltersNonSRV(t *testing.T) {
	t.Parallel()
	r := &fakeResolver{
		records: []wire.Record{
			// An A record sneaking into the SRV answer must be skipped.
			wire.NewRecord(wire.MustParseName("_amt._udp.example.com"), 60*time.Second,
				rdata.NewA(netip.MustParseAddr("192.0.2.1"))),
			wire.NewRecord(wire.MustParseName("_amt._udp.example.com"), 60*time.Second,
				rdata.NewSRV(5, 100, 2268, wire.MustParseName("relay.example.com"))),
		},
	}
	relays, err := amt.Discover(t.Context(), r, wire.MustParseName("example.com"))
	require.NoError(t, err)
	require.Len(t, relays, 1)
	require.Equal(t, "relay.example.com.", relays[0].Target.String())
}

func TestDiscover_FiltersTypeMismatch(t *testing.T) {
	t.Parallel()
	// Record advertises Type()==SRV but its RData is rdata.Unknown.
	// Discover must skip the record without panicking.
	bogus := mismatchRecord{
		name: wire.MustParseName("_amt._udp.example.com"),
		rd:   rdata.NewUnknown(rrtype.SRV, []byte{0, 1, 2, 3}),
	}
	r := &fakeResolver{
		records: []wire.Record{
			bogus,
			wire.NewRecord(wire.MustParseName("_amt._udp.example.com"), 60*time.Second,
				rdata.NewSRV(1, 0, 2268, wire.MustParseName("relay.example.com"))),
		},
	}
	relays, err := amt.Discover(t.Context(), r, wire.MustParseName("example.com"))
	require.NoError(t, err)
	require.Len(t, relays, 1)
	require.Equal(t, uint16(1), relays[0].Priority)
}

func TestDiscover_ResolverError(t *testing.T) {
	t.Parallel()
	want := errors.New("resolver boom")
	r := &fakeResolver{err: want}
	relays, err := amt.Discover(t.Context(), r, wire.MustParseName("example.com"))
	require.ErrorIs(t, err, want)
	require.Nil(t, relays)
}

func TestDiscover_NameOverflow(t *testing.T) {
	t.Parallel()
	l63 := strings.Repeat("a", 63)
	l60 := strings.Repeat("b", 60)
	long, err := wire.ParseName(l63 + "." + l63 + "." + l63 + "." + l60)
	require.NoError(t, err)
	r := &fakeResolver{}
	relays, err := amt.Discover(t.Context(), r, long)
	require.Error(t, err)
	require.Nil(t, relays)
}
