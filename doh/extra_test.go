package doh_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lestrrat-go/acidns/doh"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// newQuery builds a minimal valid query message with the given ID.
func newQuery(t *testing.T, id uint16) wire.Message {
	t.Helper()
	q, err := wire.NewBuilder().
		ID(id).
		RecursionDesired(true).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	return q
}

// TestNewURLParseError covers the url.Parse error branch in New.
func TestNewURLParseError(t *testing.T) {
	t.Parallel()
	_, err := doh.New("://")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid endpoint")
}

// TestNewNilHTTPClient covers the WithHTTPClient(nil) branch — the constructor
// must fall back to http.DefaultClient.
func TestNewNilHTTPClient(t *testing.T) {
	t.Parallel()
	ex, err := doh.New("https://example.com/dns-query", doh.WithHTTPClient(nil))
	require.NoError(t, err)
	require.NotNil(t, ex)
}

// TestExchangeBadContentType covers the unexpected-content-type branch.
func TestExchangeBadContentType(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("hello"))
	}))
	t.Cleanup(srv.Close)

	ex, err := doh.New(srv.URL)
	require.NoError(t, err)

	_, err = ex.Exchange(t.Context(), newQuery(t, 0x1234))
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected content type")
}

// TestExchangeEmptyContentType — when the server omits the Content-Type
// header, the client should still attempt to decode the body.
func TestExchangeEmptyContentType(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Force the default Content-Type detection to be suppressed by
		// sending zero bytes with no header — net/http will not set
		// Content-Type when the body is empty and no Write happens.
		w.Header()["Content-Type"] = nil
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	ex, err := doh.New(srv.URL)
	require.NoError(t, err)

	_, err = ex.Exchange(t.Context(), newQuery(t, 0x2345))
	require.Error(t, err)
	// Empty body -> wire.Unmarshal failure path.
	require.Contains(t, err.Error(), "unmarshal")
}

// TestExchangeUnmarshalError covers the wire.Unmarshal error branch with a
// well-formed Content-Type but garbage body bytes.
func TestExchangeUnmarshalError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write([]byte{0x00, 0x01}) // truncated DNS header
	}))
	t.Cleanup(srv.Close)

	ex, err := doh.New(srv.URL)
	require.NoError(t, err)

	_, err = ex.Exchange(t.Context(), newQuery(t, 0x3456))
	require.Error(t, err)
	require.Contains(t, err.Error(), "unmarshal")
}

// TestExchangeIDMismatch covers the id-mismatch error branch by having the
// server return a valid response with a different transaction ID.
func TestExchangeIDMismatch(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Build a response that is well-formed but uses a different ID.
		resp, err := wire.NewBuilder().
			ID(0xbeef). // does not match the query (0x4567)
			Response(true).
			Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
			Build()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		out, err := wire.Marshal(resp)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
	t.Cleanup(srv.Close)

	ex, err := doh.New(srv.URL)
	require.NoError(t, err)

	_, err = ex.Exchange(t.Context(), newQuery(t, 0x4567))
	require.Error(t, err)
	require.Contains(t, err.Error(), "id mismatch")
}

// TestExchangeRequestError covers the http.Client.Do error branch by pointing
// at a closed listener.
func TestExchangeRequestError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // close immediately so subsequent dial fails.

	ex, err := doh.New(url)
	require.NoError(t, err)

	_, err = ex.Exchange(t.Context(), newQuery(t, 0x5678))
	require.Error(t, err)
	require.Contains(t, err.Error(), "request")
}

// TestExchangeGETRequestError covers the GET-path http.NewRequestWithContext
// failure: passing a nil context triggers the error branch.
func TestExchangeGETRequestError(t *testing.T) {
	t.Parallel()
	ex, err := doh.New("https://example.invalid/dns-query", doh.WithMethod(doh.MethodGET))
	require.NoError(t, err)

	//nolint:staticcheck // intentionally passing nil ctx to drive error path
	_, err = ex.Exchange(nil, newQuery(t, 0x6789))
	require.Error(t, err)
}

// TestExchangePOSTRequestError covers the POST-path http.NewRequestWithContext
// failure path the same way.
func TestExchangePOSTRequestError(t *testing.T) {
	t.Parallel()
	ex, err := doh.New("https://example.invalid/dns-query")
	require.NoError(t, err)

	//nolint:staticcheck // intentionally passing nil ctx to drive error path
	_, err = ex.Exchange(nil, newQuery(t, 0x789a))
	require.Error(t, err)
}
