package webui

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"time"
)

type handler struct {
	mode      Mode
	upstreams []netip.AddrPort
	logger    *slog.Logger
}

func (h *handler) register(mux *http.ServeMux) {
	// Strip the leading "/" so http.FileServerFS serves "/" → "index.html"
	// from the assets sub-FS. Sub returns an fs.FS rooted at assets/, so a
	// request for /style.css maps to assets/style.css. The
	// embed-vs-sub-vs-strip dance avoids exposing the "assets/" path
	// segment in URLs and keeps the routing identical to a hand-rolled
	// static file mapping.
	staticFS, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		// Sub only fails if "assets" doesn't exist in the embed.FS, which
		// is a build-time invariant — assets/ is committed and embedded
		// via the //go:embed directive in assets.go. A nil handler here
		// would surface as a 500 on every static request, so we panic at
		// startup instead of silently degrading.
		panic("webui: assets/ missing from embed.FS: " + err.Error())
	}
	mux.Handle("GET /", http.FileServerFS(staticFS))
	mux.HandleFunc("GET /api/config", h.handleConfig)
	mux.HandleFunc("POST /api/query", h.handleQuery)
}

func (h *handler) handleConfig(w http.ResponseWriter, _ *http.Request) {
	type configResponse struct {
		Mode      string   `json:"mode"`
		Upstreams []string `json:"upstreams"`
		QTypes    []string `json:"qtypes"`
	}

	resp := configResponse{
		Mode:   h.mode.String(),
		QTypes: basicQTypeNames(),
	}
	resp.Upstreams = make([]string, 0, len(h.upstreams))
	for _, u := range h.upstreams {
		resp.Upstreams = append(resp.Upstreams, u.String())
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *handler) handleQuery(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var req queryRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "parse json: "+err.Error())
		return
	}

	q, err := parseQuery(&req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if h.mode == ModeBasic {
		if err := validateBasic(q, h.upstreams); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
	}

	// Cap each query at 15s so a stalled upstream can't hold the HTTP
	// connection open indefinitely. The HTTP server's own WriteTimeout
	// is a sibling guard but applies to the whole response cycle; this
	// timeout is scoped to the resolver call.
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	resp, err := execute(ctx, q)
	if err != nil {
		h.logger.Warn("webui.query.error",
			slog.String("name", q.name.String()),
			slog.String("type", q.qtype.String()),
			slog.String("error", err.Error()),
		)
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	h.logger.Debug("webui.query.ok",
		slog.String("name", q.name.String()),
		slog.String("type", q.qtype.String()),
		slog.String("rcode", resp.RCode),
		slog.Int64("elapsed_ms", resp.ElapsedMs),
	)
	writeJSON(w, http.StatusOK, resp)
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	// Pre-encode so an encode error doesn't surface mid-response after
	// the status code has been written — and so errchkjson's "unsafe
	// type any" gripe is moot: by the time we Write we hold concrete
	// bytes, not a reflective Marshal-in-the-Writer.
	buf, err := json.Marshal(body)
	if err != nil {
		http.Error(w, "internal: json marshal: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(buf)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
