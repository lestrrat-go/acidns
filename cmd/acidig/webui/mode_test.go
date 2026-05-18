package webui

import (
	"net/netip"
	"testing"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

func TestValidateBasic(t *testing.T) {
	allowed := netip.MustParseAddrPort("1.1.1.1:53")
	other := netip.MustParseAddrPort("8.8.8.8:53")
	name := wire.MustParseName("example.com")

	base := func() *parsedQuery {
		return &parsedQuery{
			name:      name,
			qtype:     rrtype.A,
			upstream:  allowed,
			transport: transportUDP,
			rd:        true,
			edns:      true,
		}
	}

	tests := []struct {
		name    string
		mutate  func(*parsedQuery)
		wantErr string
	}{
		{name: "ok", mutate: func(_ *parsedQuery) {}, wantErr: ""},
		{
			name:    "AXFR rejected",
			mutate:  func(q *parsedQuery) { q.qtype = rrtype.AXFR },
			wantErr: "type AXFR not in allow-list",
		},
		{
			name:    "ANY rejected",
			mutate:  func(q *parsedQuery) { q.qtype = rrtype.ANY },
			wantErr: "type ANY not in allow-list",
		},
		{
			name:    "unconfigured upstream rejected",
			mutate:  func(q *parsedQuery) { q.upstream = other },
			wantErr: "upstream 8.8.8.8:53 not in configured list",
		},
		{
			name:    "TCP transport allowed",
			mutate:  func(q *parsedQuery) { q.transport = transportTCP },
			wantErr: "",
		},
		{
			name:    "DoT transport allowed",
			mutate:  func(q *parsedQuery) { q.transport = transportDoT },
			wantErr: "",
		},
		{
			name:    "DoH allowed when upstream is configured (URL derived from IP)",
			mutate:  func(q *parsedQuery) { q.transport = transportDoH },
			wantErr: "",
		},
		{
			name:    "DoH with free-form URL rejected in basic mode",
			mutate:  func(q *parsedQuery) { q.transport = transportDoH; q.dohURL = "https://malicious.example/dns-query" },
			wantErr: "free-form doh_url not allowed",
		},
		{
			name:    "CD bit rejected",
			mutate:  func(q *parsedQuery) { q.cd = true },
			wantErr: "CD bit not allowed",
		},
		{
			name:    "RD off rejected",
			mutate:  func(q *parsedQuery) { q.rd = false },
			wantErr: "RD bit must be set",
		},
		{
			name:    "EDNS off rejected",
			mutate:  func(q *parsedQuery) { q.edns = false },
			wantErr: "EDNS must be enabled",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := base()
			tc.mutate(q)
			err := validateBasic(q, []netip.AddrPort{allowed})
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestParseQueryTypeAndUpstream(t *testing.T) {
	tests := []struct {
		name    string
		req     queryRequest
		want    func(*testing.T, *parsedQuery)
		wantErr string
	}{
		{
			name: "qtype_raw overrides qtype",
			req: queryRequest{
				Name:     "example.com",
				QType:    "A",
				QTypeRaw: "TYPE6",
				Upstream: "1.1.1.1:53",
			},
			want: func(t *testing.T, q *parsedQuery) {
				require.Equal(t, rrtype.SOA, q.qtype)
			},
		},
		{
			name: "bare upstream gets default port 53",
			req: queryRequest{
				Name:     "example.com",
				QType:    "A",
				Upstream: "1.1.1.1",
			},
			want: func(t *testing.T, q *parsedQuery) {
				require.Equal(t, "1.1.1.1:53", q.upstream.String())
			},
		},
		{
			name: "DoT defaults to port 853",
			req: queryRequest{
				Name:      "example.com",
				QType:     "A",
				Upstream:  "1.1.1.1",
				Transport: "dot",
				TLSName:   "cloudflare-dns.com",
			},
			want: func(t *testing.T, q *parsedQuery) {
				require.Equal(t, "1.1.1.1:853", q.upstream.String())
			},
		},
		{
			name: "DoT without tls_name accepted (server fills default)",
			req: queryRequest{
				Name:      "example.com",
				QType:     "A",
				Upstream:  "1.1.1.1:853",
				Transport: "dot",
			},
			want: func(t *testing.T, q *parsedQuery) {
				require.Equal(t, transportDoT, q.transport)
				require.Empty(t, q.tlsName)
			},
		},
		{
			name: "DoH allows blank upstream when URL is given",
			req: queryRequest{
				Name:      "example.com",
				QType:     "A",
				Transport: "doh",
				DoHURL:    "https://1.1.1.1/dns-query",
			},
			want: func(t *testing.T, q *parsedQuery) {
				require.Equal(t, transportDoH, q.transport)
				require.False(t, q.upstream.IsValid())
			},
		},
		{
			name: "DoH allows blank URL when upstream is given (URL derived later)",
			req: queryRequest{
				Name:      "example.com",
				QType:     "A",
				Upstream:  "1.1.1.1:53",
				Transport: "doh",
			},
			want: func(t *testing.T, q *parsedQuery) {
				require.Equal(t, transportDoH, q.transport)
				require.True(t, q.upstream.IsValid())
				require.Empty(t, q.dohURL)
			},
		},
		{
			name:    "name required",
			req:     queryRequest{QType: "A", Upstream: "1.1.1.1:53"},
			wantErr: "name is required",
		},
		{
			name:    "unknown rrtype",
			req:     queryRequest{Name: "example.com", QType: "NOPE", Upstream: "1.1.1.1:53"},
			wantErr: "unknown rrtype",
		},
		{
			name:    "non-IP upstream rejected",
			req:     queryRequest{Name: "example.com", QType: "A", Upstream: "dns.example.com:53"},
			wantErr: "must be a literal IP",
		},
		{
			name:    "DoH without URL OR upstream rejected",
			req:     queryRequest{Name: "example.com", QType: "A", Transport: "doh"},
			wantErr: "doh_url or upstream is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q, err := parseQuery(&tc.req)
			if tc.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			tc.want(t, q)
		})
	}
}

func TestPickTLSName(t *testing.T) {
	cf := netip.MustParseAddrPort("1.1.1.1:853")
	unknown := netip.MustParseAddrPort("100.100.100.100:53")

	t.Run("explicit name wins", func(t *testing.T) {
		name, insecure := pickTLSName("override.example", cf)
		require.Equal(t, "override.example", name)
		require.False(t, insecure)
	})
	t.Run("well-known IP fills name", func(t *testing.T) {
		name, insecure := pickTLSName("", cf)
		require.Equal(t, "cloudflare-dns.com", name)
		require.False(t, insecure)
	})
	t.Run("unknown IP falls back to insecure", func(t *testing.T) {
		name, insecure := pickTLSName("", unknown)
		require.Equal(t, "100.100.100.100", name)
		require.True(t, insecure)
	})
}

func TestPickDoHURL(t *testing.T) {
	cf := netip.MustParseAddrPort("1.1.1.1:53")
	unknown := netip.MustParseAddrPort("100.100.100.100:53")

	t.Run("explicit URL wins", func(t *testing.T) {
		url, ok := pickDoHURL("https://custom.example/dns-query", cf)
		require.True(t, ok)
		require.Equal(t, "https://custom.example/dns-query", url)
	})
	t.Run("well-known IP yields URL", func(t *testing.T) {
		url, ok := pickDoHURL("", cf)
		require.True(t, ok)
		require.Equal(t, "https://1.1.1.1/dns-query", url)
	})
	t.Run("unknown IP without explicit URL fails", func(t *testing.T) {
		_, ok := pickDoHURL("", unknown)
		require.False(t, ok)
	})
}
