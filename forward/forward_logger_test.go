package forward_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/lestrrat-go/acidns/forward"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wiretest"
	"github.com/stretchr/testify/require"
)

func TestServeDNS_LogsForwardedDecision(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	h, err := forward.New(
		forward.WithUpstream(&closableUpstream{}),
		forward.WithLogger(logger),
	)
	require.NoError(t, err)

	q := wiretest.Query(wire.MustParseName("example.com"), rrtype.A)
	h.ServeDNS(context.Background(), &captureWriter{}, q)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.NotEmpty(t, lines)
	var ev map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &ev))
	require.Equal(t, "forward.serve", ev["msg"])
	require.Equal(t, "forwarded", ev["decision"])
	require.Equal(t, "example.com.", ev["name"])
	require.Equal(t, "A", ev["type"])
}

func TestServeDNS_LogsUpstreamError(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	h, err := forward.New(
		forward.WithUpstream(&errUpstream{err: errors.New("upstream went boom")}),
		forward.WithLogger(logger),
	)
	require.NoError(t, err)

	q := wiretest.Query(wire.MustParseName("example.com"), rrtype.A)
	h.ServeDNS(context.Background(), &captureWriter{}, q)

	var ev map[string]any
	line := strings.TrimSpace(buf.String())
	require.NoError(t, json.Unmarshal([]byte(line), &ev))
	require.Equal(t, "upstream_error", ev["decision"])
	require.Equal(t, "ERROR", ev["level"])
	require.Contains(t, ev["error"], "boom")
}
