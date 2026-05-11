package doh_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lestrrat-go/acidns/doh"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/internal/wiretest"
	"github.com/stretchr/testify/require"
)

func TestWithPadding_DisablesPadding(t *testing.T) {
	t.Parallel()

	var seenLen int
	var seenPaddingOption bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenLen = len(body)
		if m, err := wire.Unmarshal(body); err == nil {
			if e, ok := m.EDNS(); ok {
				for _, opt := range e.Options() {
					if opt.Code() == wire.EDNSOptionPadding {
						seenPaddingOption = true
					}
				}
			}
			resp, _ := wiretest.Response(m)
			out, _ := wire.Marshal(resp)
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(out)
			return
		}
		http.Error(w, "bad", http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)

	ex, err := doh.New(srv.URL, doh.WithPadding(false), doh.WithInsecure(true))
	require.NoError(t, err)

	q, err := wiretest.Query(wire.MustParseName("example.com"), rrtype.A)
	require.NoError(t, err)
	_, err = ex.Exchange(context.Background(), q)
	require.NoError(t, err)
	require.False(t, seenPaddingOption, "WithPadding(false) must skip the EDNS Padding option")
	require.NotEqual(t, 0, seenLen%128, "unpadded query length should rarely land on a 128-byte boundary")
}
