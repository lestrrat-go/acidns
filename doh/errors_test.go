package doh_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lestrrat-go/acidns/doh"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wiretest"
	"github.com/stretchr/testify/require"
)

func TestExchange_HTTPStatusError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("backend down"))
	}))
	t.Cleanup(srv.Close)

	ex, err := doh.New(srv.URL, doh.WithInsecure())
	require.NoError(t, err)

	q := wiretest.Query(wire.MustParseName("example.com"), rrtype.A)
	_, err = ex.Exchange(context.Background(), q)
	require.Error(t, err)

	var hse *doh.HTTPStatusError
	require.True(t, errors.As(err, &hse), "expected *doh.HTTPStatusError, got %T: %v", err, err)
	require.Equal(t, http.StatusServiceUnavailable, hse.StatusCode)
	require.Equal(t, []byte("backend down"), hse.Body)
	require.Contains(t, hse.Error(), "503")
	require.Contains(t, hse.Error(), "backend down")
	require.Equal(t, 5, hse.Class())

	require.True(t, errors.Is(err, &doh.HTTPStatusError{StatusCode: 503}),
		"errors.Is must match by exact StatusCode")
	require.False(t, errors.Is(err, &doh.HTTPStatusError{StatusCode: 502}),
		"errors.Is must not match a different StatusCode")
}
