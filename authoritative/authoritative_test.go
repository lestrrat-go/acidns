package authoritative_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/authoritative"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/zonefile"
	"github.com/stretchr/testify/require"
)

const sampleZone = `$ORIGIN example.com.
$TTL 3600
@   IN  SOA  ns1.example.com. hostmaster.example.com. (
    2024010100 7200 3600 1209600 3600 )
@   IN  NS   ns1.example.com.
@   IN  A    192.0.2.1
ns1 IN  A    192.0.2.10
www IN  A    192.0.2.2
www IN  AAAA 2001:db8::2
mail IN A    192.0.2.3
alias IN CNAME www.example.com.
chain IN CNAME alias.example.com.
mail IN MX   10 mail.example.com.
`

func newAuth(t *testing.T) *authoritative.Authoritative {
	t.Helper()
	z, err := zonefile.Parse(strings.NewReader(sampleZone))
	require.NoError(t, err)
	a, err := authoritative.New(
		authoritative.WithZone(z),
		authoritative.WithAXFRPolicy(allowAllAXFR),
		authoritative.WithNotifyPolicy(allowAllNotify),
	)
	require.NoError(t, err)
	return a
}

// allowAllAXFR is the test allow-all AXFR policy. Production callers
// should match w.RemoteAddr() against an allow-list and/or verify TSIG.
func allowAllAXFR(_ context.Context, _ acidns.ResponseWriter, _ wire.Message) bool {
	return true
}

// allowAllNotify is the test allow-all NOTIFY policy.
func allowAllNotify(_ context.Context, _ acidns.ResponseWriter, _ wire.Message) bool {
	return true
}

// inProcWriter is a minimal ResponseWriter that captures the response.
type inProcWriter struct {
	resp    wire.Message
	network string
}

func (w *inProcWriter) WriteMsg(m wire.Message) error { w.resp = m; return nil }
func (w *inProcWriter) RemoteAddr() netip.AddrPort    { return netip.AddrPort{} }
func (w *inProcWriter) LocalAddr() netip.AddrPort     { return netip.AddrPort{} }
func (w *inProcWriter) Network() string {
	if w.network == "" {
		return "tcp"
	}
	return w.network
}

func ask(t *testing.T, a acidns.Handler, name string, rt rrtype.Type) wire.Message {
	t.Helper()
	q, err := wire.NewBuilder().
		ID(1).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName(name), rt)).
		Build()
	require.NoError(t, err)
	w := &inProcWriter{}
	a.ServeDNS(context.Background(), w, q)
	require.NotNil(t, w.resp)
	return w.resp
}

func TestExactMatchA(t *testing.T) {
	t.Parallel()
	a := newAuth(t)
	resp := ask(t, a, "www.example.com", rrtype.A)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
	require.True(t, resp.Flags().Authoritative())
	require.Equal(t, 1, len(resp.Answers()))
	require.Equal(t, "192.0.2.2", resp.Answers()[0].RData().(rdata.A).Addr().String())
}

func TestNODATA(t *testing.T) {
	t.Parallel()
	a := newAuth(t)
	resp := ask(t, a, "mail.example.com", rrtype.AAAA) // mail has A but not AAAA
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
	require.Equal(t, 0, len(resp.Answers()))
	require.Equal(t, 1, len(resp.Authorities()))
	require.Equal(t, rrtype.SOA, resp.Authorities()[0].Type())
}

func TestNXDOMAIN(t *testing.T) {
	t.Parallel()
	a := newAuth(t)
	resp := ask(t, a, "nope.example.com", rrtype.A)
	require.Equal(t, wire.RCODENXDomain, resp.Flags().RCODE())
	require.Equal(t, 0, len(resp.Answers()))
	require.Equal(t, 1, len(resp.Authorities()))
	require.Equal(t, rrtype.SOA, resp.Authorities()[0].Type())
}

func TestRefused(t *testing.T) {
	t.Parallel()
	a := newAuth(t)
	resp := ask(t, a, "example.org", rrtype.A) // outside zone
	require.Equal(t, wire.RCODERefused, resp.Flags().RCODE())
	require.False(t, resp.Flags().Authoritative())
}

func TestCNAMEChase(t *testing.T) {
	t.Parallel()
	a := newAuth(t)
	resp := ask(t, a, "alias.example.com", rrtype.A)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
	require.Equal(t, 2, len(resp.Answers()))
	require.Equal(t, rrtype.CNAME, resp.Answers()[0].Type())
	require.Equal(t, rrtype.A, resp.Answers()[1].Type())
	require.Equal(t, "192.0.2.2", resp.Answers()[1].RData().(rdata.A).Addr().String())
}

func TestCNAMEChainOfTwo(t *testing.T) {
	t.Parallel()
	a := newAuth(t)
	resp := ask(t, a, "chain.example.com", rrtype.A)
	require.Equal(t, wire.RCODENoError, resp.Flags().RCODE())
	// chain → alias → www, then A
	require.Equal(t, 3, len(resp.Answers()))
	require.Equal(t, rrtype.CNAME, resp.Answers()[0].Type())
	require.Equal(t, rrtype.CNAME, resp.Answers()[1].Type())
	require.Equal(t, rrtype.A, resp.Answers()[2].Type())
}

func TestCNAMEDirect(t *testing.T) {
	t.Parallel()
	// Direct CNAME query returns just the CNAME, no chase.
	a := newAuth(t)
	resp := ask(t, a, "alias.example.com", rrtype.CNAME)
	require.Equal(t, 1, len(resp.Answers()))
	require.Equal(t, rrtype.CNAME, resp.Answers()[0].Type())
}

func TestZoneWithoutSOAFails(t *testing.T) {
	t.Parallel()
	in := `$ORIGIN bogus.example.
$TTL 60
@ IN A 192.0.2.99
`
	z, err := zonefile.Parse(strings.NewReader(in))
	require.NoError(t, err)
	_, err = authoritative.New(authoritative.WithZone(z))
	require.ErrorIs(t, err, authoritative.ErrNoSOA)
}
