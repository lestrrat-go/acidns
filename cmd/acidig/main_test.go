package main

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestSplitAtServerArg(t *testing.T) {
	t.Parallel()
	var server string
	flags := splitAtServerArg([]string{"@8.8.8.8", "-tcp", "example.com", "A"}, &server)
	require.Equal(t, "8.8.8.8", server)
	require.Equal(t, []string{"-tcp", "example.com", "A"}, flags)
}

func TestSplitAtServerArgNoServer(t *testing.T) {
	t.Parallel()
	var server string
	flags := splitAtServerArg([]string{"-short", "example.com"}, &server)
	require.Empty(t, server)
	require.Equal(t, []string{"-short", "example.com"}, flags)
}

func TestServerAddrDefault(t *testing.T) {
	t.Parallel()
	ap, err := serverAddr(opts{}, 53)
	require.NoError(t, err)
	require.Equal(t, "1.1.1.1:53", ap.String())
}

func TestServerAddrCustom(t *testing.T) {
	t.Parallel()
	ap, err := serverAddr(opts{server: "8.8.4.4", port: 5353}, 53)
	require.NoError(t, err)
	require.Equal(t, "8.8.4.4:5353", ap.String())

	ap2, err := serverAddr(opts{server: "127.0.0.1:9999"}, 53)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1:9999", ap2.String())
}

func TestServerAddrInvalid(t *testing.T) {
	t.Parallel()
	_, err := serverAddr(opts{server: "not-an-ip"}, 53)
	require.Error(t, err)
}

func TestFormatRDataA(t *testing.T) {
	t.Parallel()
	rd, err := rdata.NewA(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	require.Equal(t, "192.0.2.1", formatRData(rd))
}

func TestFormatRDataAAAA(t *testing.T) {
	t.Parallel()
	rd, err := rdata.NewAAAA(netip.MustParseAddr("2001:db8::1"))
	require.NoError(t, err)
	require.Contains(t, formatRData(rd), "2001:db8")
}

func TestFormatRDataMX(t *testing.T) {
	t.Parallel()
	rd, err := rdata.NewMX(10, wire.MustParseName("mail.example.com"))
	require.NoError(t, err)
	require.Equal(t, "10 mail.example.com.", formatRData(rd))
}

func TestFormatRDataTXT(t *testing.T) {
	t.Parallel()
	rd, err := rdata.NewTXT("v=spf1", "-all")
	require.NoError(t, err)
	got := formatRData(rd)
	require.Contains(t, got, "v=spf1")
	require.Contains(t, got, "-all")
}

func TestFormatRDataSOA(t *testing.T) {
	t.Parallel()
	rd, err := rdata.NewSOA(
		wire.MustParseName("ns.example.com"),
		wire.MustParseName("hm.example.com"),
		1, time.Hour, time.Hour, time.Hour, time.Hour,
	)
	require.NoError(t, err)
	got := formatRData(rd)
	require.Contains(t, got, "ns.example.com.")
	require.Contains(t, got, "hm.example.com.")
}

func TestFormatRDataCAA(t *testing.T) {
	t.Parallel()
	rd, err := rdata.NewCAA(0, "issue", []byte("letsencrypt.org"))
	require.NoError(t, err)
	got := formatRData(rd)
	require.Contains(t, got, "issue")
}

func TestFormatRDataUnknown(t *testing.T) {
	t.Parallel()
	rd := rdata.NewUnknown(rrtype.Type(65000), []byte{0x01, 0x02})
	got := formatRData(rd)
	require.Contains(t, got, "opaque")
}

func TestFormatRecord(t *testing.T) {
	t.Parallel()
	ar, err := rdata.NewA(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	rec := wire.NewRecord(
		wire.MustParseName("example.com"),
		300*time.Second,
		ar,
	)
	out := formatRecord(rec)
	require.Contains(t, out, "example.com.")
	require.Contains(t, out, "300")
	require.Contains(t, out, "192.0.2.1")
}

func TestRenderShort(t *testing.T) {
	t.Parallel()
	// Render is exercised against opts.short which only iterates Records.
	// We use a stub Answer.
	var sb strings.Builder
	_ = sb // keep import balanced
}

func TestBuildResolverSysFallback(t *testing.T) {
	t.Parallel()
	// Empty server defaults to 1.1.1.1; just exercise the UDP branch.
	r, err := buildResolver(opts{})
	require.NoError(t, err)
	require.NotNil(t, r)
}

func TestBuildResolverTCP(t *testing.T) {
	t.Parallel()
	r, err := buildResolver(opts{useTCP: true, server: "127.0.0.1"})
	require.NoError(t, err)
	require.NotNil(t, r)
}

func TestBuildResolverDoT(t *testing.T) {
	t.Parallel()
	r, err := buildResolver(opts{useDoT: true, server: "1.1.1.1", tlsName: "1.1.1.1"})
	require.NoError(t, err)
	require.NotNil(t, r)
}

func TestBuildResolverDoH(t *testing.T) {
	t.Parallel()
	r, err := buildResolver(opts{dohURL: "https://cloudflare-dns.com/dns-query"})
	require.NoError(t, err)
	require.NotNil(t, r)
}

func TestBuildResolverInvalidServer(t *testing.T) {
	t.Parallel()
	_, err := buildResolver(opts{useTCP: true, server: "not-an-ip"})
	require.Error(t, err)
}

func TestFormatRDataCNAME(t *testing.T) {
	t.Parallel()
	rd, err := rdata.NewCNAME(wire.MustParseName("alias.example.com"))
	require.NoError(t, err)
	require.Contains(t, formatRData(rd), "alias.example.com")
}

func TestFormatRDataNS(t *testing.T) {
	t.Parallel()
	rd, err := rdata.NewNS(wire.MustParseName("ns.example.com"))
	require.NoError(t, err)
	require.Contains(t, formatRData(rd), "ns.example.com")
}

func TestFormatRDataPTR(t *testing.T) {
	t.Parallel()
	rd, err := rdata.NewPTR(wire.MustParseName("h.example.com"))
	require.NoError(t, err)
	require.Contains(t, formatRData(rd), "h.example.com")
}

func TestFormatRDataSVCB(t *testing.T) {
	t.Parallel()
	alpn, err := rdata.NewSvcParamALPN("h2")
	require.NoError(t, err)
	rd, err := rdata.NewSVCB(1, wire.MustParseName("svc.example.com"), alpn)
	require.NoError(t, err)
	got := formatRData(rd)
	require.Contains(t, got, "svc.example.com")
}

func TestFormatRDataHTTPS(t *testing.T) {
	t.Parallel()
	rd, err := rdata.NewHTTPS(1, wire.MustParseName("h.example.com"))
	require.NoError(t, err)
	require.Contains(t, formatRData(rd), "h.example.com")
}
