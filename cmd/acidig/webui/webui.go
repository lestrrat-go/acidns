// Package webui implements the acidig --web HTTP UI. It is an
// internal sub-package of cmd/acidig and is not part of the acidns
// public API.
//
// The package exposes a single entry point, [Run], which starts an
// http.Server bound to the configured listen address. The server
// renders an embedded HTML form that POSTs to /api/query; the handler
// translates the request into a DNS query against an upstream chosen
// either from the basic-mode allow-list (resolv.conf + --web-upstream)
// or, in advanced mode, any user-supplied address and transport.
package webui

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/lestrrat-go/acidns/resolvconf"
)

// Config is the runtime configuration for [Run]. Construct it from
// acidig's CLI flags and pass by value.
type Config struct {
	// Listen is the TCP address the HTTP server binds to. Empty falls
	// back to 127.0.0.1:8053.
	Listen string

	// Mode picks the basic / advanced UI surface. The handler also
	// re-validates each request against the mode, so client-side
	// gating is UX, not the trust boundary.
	Mode Mode

	// ExtraUpstreams are additional upstream candidates appended to
	// the basic-mode dropdown (in addition to /etc/resolv.conf
	// nameservers). They are also accepted as valid targets in
	// basic-mode requests.
	ExtraUpstreams []netip.AddrPort

	// NoDefaultUpstreams suppresses the always-on public-resolver
	// seed (1.1.1.1, 8.8.8.8, 9.9.9.9). Set this when you want the
	// dropdown to expose only what /etc/resolv.conf and
	// ExtraUpstreams provide — e.g. an air-gapped demo with a single
	// approved upstream.
	NoDefaultUpstreams bool

	// Logger receives structured per-request events. nil = discard.
	Logger *slog.Logger
}

// Run starts the web UI server and blocks until ctx is cancelled or
// the HTTP server fails. It performs a graceful shutdown bounded by a
// short timeout on ctx cancellation.
func Run(ctx context.Context, cfg Config) error {
	listen := cfg.Listen
	if listen == "" {
		listen = "127.0.0.1:8053"
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	// Order: public defaults first (always work for any transport),
	// then system resolv.conf, then explicit --web-upstream entries.
	// Dedup preserves first occurrence so the default selection in
	// the dropdown is the most-likely-to-work option.
	var upstreams []netip.AddrPort
	if !cfg.NoDefaultUpstreams {
		upstreams = append(upstreams, publicDefaultUpstreams...)
	}
	upstreams = append(upstreams, loadSystemUpstreams(logger)...)
	upstreams = append(upstreams, cfg.ExtraUpstreams...)
	upstreams = dedupAddrPorts(upstreams)

	h := &handler{
		mode:      cfg.Mode,
		upstreams: upstreams,
		logger:    logger,
	}

	mux := http.NewServeMux()
	h.register(mux)

	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", listen)
	if err != nil {
		return fmt.Errorf("acidig --web: listen %s: %w", listen, err)
	}

	fmt.Fprintf(os.Stderr, "acidig --web: mode=%s listening on http://%s/\n", cfg.Mode, ln.Addr())
	if cfg.Mode == ModeAdvanced {
		fmt.Fprintln(os.Stderr, "acidig --web: advanced mode enabled — dangerous features unlocked")
	}
	if len(upstreams) == 0 {
		fmt.Fprintln(os.Stderr, "acidig --web: warning: no upstreams configured (--web-no-defaults set with empty /etc/resolv.conf and no --web-upstream); basic mode will reject every query")
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func loadSystemUpstreams(logger *slog.Logger) []netip.AddrPort {
	cfg, err := resolvconf.Load("")
	if err != nil {
		logger.Debug("webui.resolvconf.load", slog.String("error", err.Error()))
		return nil
	}
	return cfg.Nameservers()
}

func dedupAddrPorts(in []netip.AddrPort) []netip.AddrPort {
	seen := make(map[netip.AddrPort]struct{}, len(in))
	out := make([]netip.AddrPort, 0, len(in))
	for _, ap := range in {
		if _, ok := seen[ap]; ok {
			continue
		}
		seen[ap] = struct{}{}
		out = append(out, ap)
	}
	return out
}
