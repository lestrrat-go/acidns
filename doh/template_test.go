package doh_test

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/doh"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// templateProbeServer answers any GET on the canonical /dns-query path
// regardless of which RFC 6570 template form the client used. It echoes
// the wire-format request in the response so the test can assert the
// dns parameter was carried correctly.
func templateProbeServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != "/dns-query" {
			http.Error(w, "wrong path "+r.URL.Path, http.StatusNotFound)
			return
		}
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, "missing dns", http.StatusBadRequest)
			return
		}
		raw, err := base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req, err := wire.Unmarshal(raw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ar, err := rdata.NewA(netip.MustParseAddr("198.51.100.7"))
		require.NoError(t, err)
		resp, _ := wire.NewMessageBuilder().
			ID(req.ID()).
			Response(true).
			Question(req.Questions()[0]).
			Answer(wire.NewRecord(req.Questions()[0].Name(), time.Minute,
				ar)).
			Build()
		out, _ := wire.Marshal(resp)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
}

// pathProbeServer answers GET /dns-query/<base64url>; it is used to
// exercise the {dns} path-style expansion form. There is no "?dns="
// fallback here — the literal-path GET must arrive verbatim.
func pathProbeServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/dns-query/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.Error(w, "wrong path "+r.URL.Path, http.StatusNotFound)
			return
		}
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(r.URL.Path, prefix))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req, err := wire.Unmarshal(raw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_ = body
		ar2, err := rdata.NewA(netip.MustParseAddr("198.51.100.7"))
		require.NoError(t, err)
		resp, _ := wire.NewMessageBuilder().
			ID(req.ID()).
			Response(true).
			Question(req.Questions()[0]).
			Answer(wire.NewRecord(req.Questions()[0].Name(), time.Minute,
				ar2)).
			Build()
		out, _ := wire.Marshal(resp)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
}

func TestGETFormTemplate(t *testing.T) {
	t.Parallel()
	srv := templateProbeServer(t)
	t.Cleanup(srv.Close)

	endpoint := srv.URL + "/dns-query{?dns}"
	ex, err := doh.NewClient(endpoint, doh.WithMethod(doh.MethodGET), doh.WithInsecure(true))
	require.NoError(t, err)

	q, _ := wire.NewMessageBuilder().
		ID(0xface).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	resp, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, q.ID(), resp.ID())
}

func TestGETPathTemplate(t *testing.T) {
	t.Parallel()
	srv := pathProbeServer(t)
	t.Cleanup(srv.Close)

	endpoint := srv.URL + "/dns-query/{dns}"
	ex, err := doh.NewClient(endpoint, doh.WithMethod(doh.MethodGET), doh.WithInsecure(true))
	require.NoError(t, err)

	q, _ := wire.NewMessageBuilder().
		ID(0xbeef).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	resp, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, q.ID(), resp.ID())
}

func TestGETLegacyAppendQuery(t *testing.T) {
	t.Parallel()
	srv := templateProbeServer(t)
	t.Cleanup(srv.Close)

	endpoint := srv.URL + "/dns-query"
	ex, err := doh.NewClient(endpoint, doh.WithMethod(doh.MethodGET), doh.WithInsecure(true))
	require.NoError(t, err)

	q, _ := wire.NewMessageBuilder().
		ID(0xc0de).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	resp, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, q.ID(), resp.ID())
}
