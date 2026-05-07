package amt_test

import (
	"context"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/amt"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

type fakeResolver struct{ records []wire.Record }

type fakeAnswer struct{ records []wire.Record }

func (f *fakeAnswer) Question() wire.Question { return nil }
func (f *fakeAnswer) Records() []wire.Record  { return f.records }
func (f *fakeAnswer) Raw() wire.Message       { return nil }
func (f *fakeAnswer) RCODE() wire.RCODE       { return wire.RCODENoError }
func (f *fakeAnswer) Authoritative() bool     { return false }
func (f *fakeAnswer) Truncated() bool         { return false }

func (f *fakeResolver) Resolve(_ context.Context, _ wire.Name, _ rrtype.Type) (acidns.Answer, error) {
	return &fakeAnswer{records: f.records}, nil
}

func TestDiscoveryName(t *testing.T) {
	t.Parallel()
	n, err := amt.DiscoveryName(wire.MustParseName("example.com"))
	require.NoError(t, err)
	require.Equal(t, "_amt._udp.example.com.", n.String())
}

func TestDiscover(t *testing.T) {
	t.Parallel()
	r := &fakeResolver{
		records: []wire.Record{
			wire.NewRecord(wire.MustParseName("_amt._udp.example.com"), 60*time.Second,
				rdata.NewSRV(20, 0, 2268, wire.MustParseName("relay-b.example.com"))),
			wire.NewRecord(wire.MustParseName("_amt._udp.example.com"), 60*time.Second,
				rdata.NewSRV(10, 0, 2268, wire.MustParseName("relay-a.example.com"))),
		},
	}
	relays, err := amt.Discover(context.Background(), r, wire.MustParseName("example.com"))
	require.NoError(t, err)
	require.Len(t, relays, 2)
	require.Equal(t, uint16(10), relays[0].Priority)
	require.Equal(t, "relay-a.example.com.", relays[0].Target.String())
}
