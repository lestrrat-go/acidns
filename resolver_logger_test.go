package acidns_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/internal/wiretest"
	"github.com/stretchr/testify/require"
)

type echoExchanger struct{}

func (echoExchanger) Exchange(_ context.Context, q wire.Message) (wire.Message, error) {
	return wiretest.Response(q)
}

func TestResolver_LogsResolveDebug(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	r, err := acidns.NewResolver(
		acidns.WithExchanger(echoExchanger{}),
		acidns.WithLogger(logger),
	)
	require.NoError(t, err)

	_, err = r.Resolve(t.Context(), wire.MustParseName("example.com"), rrtype.A)
	require.NoError(t, err)

	var ev map[string]any
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &ev))
	require.Equal(t, "resolver.resolve", ev["msg"])
	require.Equal(t, "DEBUG", ev["level"])
	require.Equal(t, "example.com.", ev["name"])
	require.Equal(t, "A", ev["type"])
}

func TestResolver_LogsExchangeError(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	r, err := acidns.NewResolver(
		acidns.WithExchanger(&stubExchanger{err: errors.New("network down")}),
		acidns.WithLogger(logger),
	)
	require.NoError(t, err)

	_, err = r.Resolve(t.Context(), wire.MustParseName("example.com"), rrtype.A)
	require.Error(t, err)

	var ev map[string]any
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &ev))
	require.Equal(t, "ERROR", ev["level"])
	require.Contains(t, ev["error"], "network down")
}

func TestResolver_LogsRCODE(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	q, err := wiretest.Query(wire.MustParseName("nope.example.com"), rrtype.A)
	require.NoError(t, err)
	resp, err := wiretest.NXDOMAIN(q)
	require.NoError(t, err)

	r, err := acidns.NewResolver(
		acidns.WithExchanger(&stubExchanger{resp: resp}),
		acidns.WithLogger(logger),
	)
	require.NoError(t, err)

	_, err = r.Resolve(t.Context(), wire.MustParseName("nope.example.com"), rrtype.A)
	require.Error(t, err)

	var ev map[string]any
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &ev))
	require.Equal(t, "WARN", ev["level"])
	require.Contains(t, ev["rcode"], "NXDOMAIN")
}
