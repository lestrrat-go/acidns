package doh_test

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnsclient/transport/doh"
	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/stretchr/testify/require"
)

func makeServer(t *testing.T, expectedMethod string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != expectedMethod {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var wire []byte
		switch r.Method {
		case http.MethodPost:
			b, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			wire = b
		case http.MethodGet:
			dec, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			wire = dec
		}
		req, err := dnsmsg.Unmarshal(wire)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		resp, _ := dnsmsg.NewBuilder().
			ID(req.ID()).
			Response(true).
			Question(req.Questions()[0]).
			Answer(dnsmsg.NewRecord(req.Questions()[0].Name(), time.Minute,
				rdata.NewA(netip.MustParseAddr("198.51.100.99")))).
			Build()
		out, _ := dnsmsg.Marshal(resp)
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(out)
	}))
}

func TestDoHPost(t *testing.T) {
	t.Parallel()
	srv := makeServer(t, http.MethodPost)
	t.Cleanup(srv.Close)

	ex, err := doh.New(srv.URL + "/dns-query")
	require.NoError(t, err)

	q, _ := dnsmsg.NewBuilder().
		ID(0x55aa).
		RecursionDesired(true).
		Question(dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.A)).
		Build()
	resp, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, q.ID(), resp.ID())
	require.Equal(t, "198.51.100.99", resp.Answers()[0].RData().(rdata.A).Addr().String())
}

func TestDoHGet(t *testing.T) {
	t.Parallel()
	srv := makeServer(t, http.MethodGet)
	t.Cleanup(srv.Close)

	ex, err := doh.New(srv.URL+"/dns-query", doh.WithMethod(doh.MethodGET))
	require.NoError(t, err)

	q, _ := dnsmsg.NewBuilder().
		ID(0xcafe).
		RecursionDesired(true).
		Question(dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.A)).
		Build()
	resp, err := ex.Exchange(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, q.ID(), resp.ID())
}

func TestDoHHTTPError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	ex, err := doh.New(srv.URL)
	require.NoError(t, err)

	q, _ := dnsmsg.NewBuilder().
		ID(1).
		Question(dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.A)).
		Build()
	_, err = ex.Exchange(t.Context(), q)
	require.Error(t, err)
}

func TestDoHContextCancel(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)

	ex, err := doh.New(srv.URL)
	require.NoError(t, err)

	q, _ := dnsmsg.NewBuilder().
		ID(1).
		Question(dnsmsg.NewQuestion(dnsname.MustParse("example.com"), rrtype.A)).
		Build()

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	_, err = ex.Exchange(ctx, q)
	require.Error(t, err)
}

func TestDoHInvalidEndpoint(t *testing.T) {
	t.Parallel()
	_, err := doh.New("not a url")
	require.Error(t, err)
	_, err = doh.New("ftp://example.com")
	require.Error(t, err)
	_, err = url.Parse("https://valid.example/")
	require.NoError(t, err)
}
