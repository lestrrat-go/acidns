package amt_test

import (
	"context"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient"
	"github.com/lestrrat-go/acidns/dnsclient/amt"
	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/stretchr/testify/require"
)

type fakeResolver struct{ records []dnsmsg.Record }

type fakeAnswer struct{ records []dnsmsg.Record }

func (f *fakeAnswer) Question() dnsmsg.Question { return nil }
func (f *fakeAnswer) Records() []dnsmsg.Record  { return f.records }
func (f *fakeAnswer) Raw() dnsmsg.Message       { return nil }
func (f *fakeAnswer) RCODE() dnsmsg.RCODE       { return dnsmsg.RCODENoError }
func (f *fakeAnswer) Authoritative() bool       { return false }
func (f *fakeAnswer) Truncated() bool           { return false }

func (f *fakeResolver) Resolve(_ context.Context, _ dnsname.Name, _ rrtype.Type) (dnsclient.Answer, error) {
	return &fakeAnswer{records: f.records}, nil
}

func TestDiscoveryName(t *testing.T) {
	t.Parallel()
	n, err := amt.DiscoveryName(dnsname.MustParse("example.com"))
	require.NoError(t, err)
	require.Equal(t, "_amt._udp.example.com.", n.String())
}

func TestDiscover(t *testing.T) {
	t.Parallel()
	r := &fakeResolver{
		records: []dnsmsg.Record{
			dnsmsg.NewRecord(dnsname.MustParse("_amt._udp.example.com"), 60*time.Second,
				rdata.NewSRV(20, 0, 2268, dnsname.MustParse("relay-b.example.com"))),
			dnsmsg.NewRecord(dnsname.MustParse("_amt._udp.example.com"), 60*time.Second,
				rdata.NewSRV(10, 0, 2268, dnsname.MustParse("relay-a.example.com"))),
		},
	}
	relays, err := amt.Discover(context.Background(), r, dnsname.MustParse("example.com"))
	require.NoError(t, err)
	require.Len(t, relays, 2)
	require.Equal(t, uint16(10), relays[0].Priority)
	require.Equal(t, "relay-a.example.com.", relays[0].Target.String())
}
