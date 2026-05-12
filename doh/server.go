package doh

// DoH server. Two layers:
//
//   - [NewHandler] returns an http.Handler that decodes RFC 8484
//     wire-format requests, dispatches to the supplied
//     [acidns.Handler], and writes the wire-format response back
//     under Content-Type: application/dns-message. Compose this with
//     any net/http server you already operate.
//
//   - [NewServer] / [Server.Run] is a convenience wrapper that
//     constructs an http.Server with the bundled handler, sane
//     TLS-1.3 / ALPN h2 + http/1.1 defaults, and a Run(ctx)
//     lifecycle that mirrors the rest of the acidns server family.
//
// # RFC 8484 conformance
//
// Both POST and GET are accepted (§4.1). For POST, the request body
// is the wire-format query — Content-Type MUST be
// application/dns-message; otherwise 415. For GET, the wire-format
// query is base64url-encoded with no padding in a "dns" query
// parameter; the handler accepts only the canonical no-padding
// form. The response always carries Content-Type:
// application/dns-message.
//
// # Panic policy divergence
//
// The rest of the acidns server family lets handler panics propagate
// to the listener goroutine and ultimately the process — see
// [acidns.Handler]. DoH is the exception: the handler runs under
// [net/http.Server], whose accept loop installs an unconditional
// recover() that turns a panicking handler into a 500 response and
// a stderr log entry. Removing that recover would require
// reimplementing http.Server, which is out of scope.
//
// What this means for operators:
//
//   - A panic in the [acidns.Handler] will NOT crash the process via
//     this transport. Other transports will.
//   - For uniform crash semantics, wrap your inner Handler with a
//     middleware that re-raises after logging — but be aware that
//     re-panicking is also caught by net/http, so the only way to
//     reach the process is os.Exit / panic+os.Exit from a separate
//     goroutine.
//
// In practice this divergence is benign: a handler that can panic
// is buggy in any case, and HTTP-style 500 + log is usually what an
// operator actually wants for HTTP-shaped traffic.

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"golang.org/x/net/http2"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/internal/serverctl"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/option/v3"
)

// ErrServerClosed is recorded on the [Controller] after a clean
// shutdown via context cancellation. Aliased to
// [acidns.ErrServerClosed] so transport-agnostic callers can match
// either form via errors.Is.
var ErrServerClosed = acidns.ErrServerClosed

// MaxRequestBytes caps the request body the handler is willing to
// read. RFC 8484 carries one DNS message, whose wire form is
// bounded by the 16-bit length field plus a small slack for HTTP
// framing variations. A hostile client could otherwise stream
// gigabytes past wire.Unpack's rejection.
const MaxRequestBytes = 64 * 1024

// NewHandler returns an http.Handler that serves DoH requests by
// dispatching to h.
func NewHandler(h acidns.Handler, opts ...HandlerOption) http.Handler {
	if h == nil {
		// Degrade to a 500 handler so a misuse is loud rather than
		// silent. Returning nil would NPE inside ServeMux.
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "doh: handler is nil", http.StatusInternalServerError)
		})
	}
	c := handlerConfig{maxRequestBytes: MaxRequestBytes}
	for _, o := range opts {
		switch o.Ident() {
		case identHandlerMaxRequestBytes{}:
			c.maxRequestBytes = option.MustGet[int](o)
		}
	}
	if c.maxRequestBytes <= 0 {
		c.maxRequestBytes = MaxRequestBytes
	}
	return &dohHandler{h: h, cfg: c}
}

type dohHandler struct {
	h   acidns.Handler
	cfg handlerConfig
}

func (h *dohHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := h.readRequest(r)
	if err != nil {
		writeHTTPError(w, err)
		return
	}

	q, err := wire.Unpack(body)
	if err != nil {
		http.Error(w, "doh: malformed DNS message", http.StatusBadRequest)
		return
	}

	rw := &dohResponseWriter{
		http:   w,
		remote: remoteAddr(r),
		local:  localAddr(r),
	}
	switch verdict, reply := acidns.PreflightRequest(q); verdict {
	case acidns.PreflightDrop:
		// HTTP can't drop silently — the client is waiting for a
		// response. The closest analogue is a 400 with no body so
		// the client doesn't get a useful retry signal.
		http.Error(w, "doh: response in request slot", http.StatusBadRequest)
		return
	case acidns.PreflightReply:
			_ = rw.WriteMsg(reply)
		return
	}
	h.h.ServeDNS(r.Context(), rw, q)
	if !rw.wrote {
		// Handler returned without writing — emit a SERVFAIL so the
		// client sees a deterministic outcome rather than a hung HTTP
		// connection. RFC 8484 has no notion of "no answer."
		fb, _ := wire.NewMessageBuilder().ID(q.ID()).Response(true).RCODE(wire.RCODEServFail).Build()
		_ = rw.WriteMsg(fb)
	}
}

func (h *dohHandler) readRequest(r *http.Request) ([]byte, error) {
	switch r.Method {
	case http.MethodPost:
		// RFC 8484 §6 permits parameters on Content-Type
		// (e.g. "application/dns-message; charset=utf-8"); a raw string
		// compare against the canonical form would 415 those.
		mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mt != contentType {
			return nil, &httpProblem{status: http.StatusUnsupportedMediaType, msg: "doh: Content-Type must be " + contentType}
		}
		// Refuse oversized advertised bodies before reading.
		if cl := r.ContentLength; cl > int64(h.cfg.maxRequestBytes) {
			return nil, &httpProblem{status: http.StatusRequestEntityTooLarge, msg: "doh: request body exceeds size cap"}
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, int64(h.cfg.maxRequestBytes)+1))
		if err != nil {
			return nil, err
		}
		if len(body) > h.cfg.maxRequestBytes {
			return nil, &httpProblem{status: http.StatusRequestEntityTooLarge, msg: "doh: request body exceeds size cap"}
		}
		return body, nil
	case http.MethodGet:
		// RFC 8484 §4.1: base64url-encoded "dns" query parameter, no
		// padding. The Go base64 package's RawURLEncoding rejects
		// padding by default — use it as the canonical decoder.
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			return nil, &httpProblem{status: http.StatusBadRequest, msg: "doh: missing dns query parameter"}
		}
		if len(dnsParam) > base64.RawURLEncoding.EncodedLen(h.cfg.maxRequestBytes) {
			return nil, &httpProblem{status: http.StatusRequestEntityTooLarge, msg: "doh: dns parameter exceeds size cap"}
		}
		return base64.RawURLEncoding.DecodeString(dnsParam)
	default:
		return nil, &httpProblem{status: http.StatusMethodNotAllowed, msg: "doh: method not allowed"}
	}
}

type httpProblem struct {
	status int
	msg    string
}

func (p *httpProblem) Error() string { return p.msg }

func writeHTTPError(w http.ResponseWriter, err error) {
	var p *httpProblem
	if errors.As(err, &p) {
		http.Error(w, p.msg, p.status)
		return
	}
	http.Error(w, err.Error(), http.StatusBadRequest)
}

// dohResponseWriter implements [acidns.ResponseWriter] over an
// http.ResponseWriter. The wire-format DNS response is written as the
// HTTP body with the canonical Content-Type. The HTTP body is
// flushed on the first WriteMsg call; subsequent WriteMsg calls
// return an error because HTTP carries one response per request.
type dohResponseWriter struct {
	http   http.ResponseWriter
	remote netip.AddrPort
	local  netip.AddrPort
	wrote  bool
}

func (w *dohResponseWriter) RemoteAddr() netip.AddrPort { return w.remote }
func (w *dohResponseWriter) LocalAddr() netip.AddrPort  { return w.local }
func (w *dohResponseWriter) Network() string            { return "doh" }

func (w *dohResponseWriter) WriteMsg(m wire.Message) error {
	if w.wrote {
		return ErrDuplicateWrite
	}
	w.wrote = true
	buf, err := wire.Pack(m)
	if err != nil {
		http.Error(w.http, "doh: marshal error", http.StatusInternalServerError)
		return err
	}
	w.http.Header().Set("Content-Type", contentType)
	w.http.WriteHeader(http.StatusOK)
	_, err = w.http.Write(buf)
	return err
}

// remoteAddr returns the client's address as a netip.AddrPort,
// preferring the parsed *net.TCPAddr form so the address survives
// any IPv6 zone-id formatting variation.
func remoteAddr(r *http.Request) netip.AddrPort {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap
	}
	return netip.AddrPort{}
}

func localAddr(r *http.Request) netip.AddrPort {
	if la, ok := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr); ok {
		return la.AddrPort()
	}
	return netip.AddrPort{}
}

// Server is the convenience wrapper around an http.Server that runs
// the DoH handler with sane defaults. Operators with their own HTTP
// machinery should compose [NewHandler] into their existing
// http.ServeMux instead.
type Server struct {
	addr    netip.AddrPort
	handler acidns.Handler
	cfg     serverConfig
}

// NewServer returns a Server. tls.Config is required (DoH without
// HTTPS isn't DoH); set its Certificates and ServerName as needed.
// The path the handler responds on is configurable via
// [WithServerPath]; default is "/dns-query" per RFC 8484 §3.
func NewServer(addr netip.AddrPort, h acidns.Handler, opts ...ServerOption) (*Server, error) {
	if h == nil {
		return nil, ErrNilHandler
	}
	cfg := serverConfig{
		path:                 "/dns-query",
		maxRequestBytes:      MaxRequestBytes,
		readHeaderTimeout:    10 * time.Second,
		readTimeout:          30 * time.Second,
		writeTimeout:         30 * time.Second,
		idleTimeout:          60 * time.Second,
		maxConnections:       1024,
		maxConnsPerSource:    32,
		maxConcurrentStreams: 32,
	}
	for _, o := range opts {
		switch o.Ident() {
		case identServerTLSConfig{}:
			cfg.tlsConfig = option.MustGet[*tls.Config](o)
		case identServerPath{}:
			cfg.path = option.MustGet[string](o)
		case identServerMaxRequestBytes{}:
			cfg.maxRequestBytes = option.MustGet[int](o)
		case identServerReadHeaderTimeout{}:
			cfg.readHeaderTimeout = option.MustGet[time.Duration](o)
		case identServerReadTimeout{}:
			cfg.readTimeout = option.MustGet[time.Duration](o)
		case identServerWriteTimeout{}:
			cfg.writeTimeout = option.MustGet[time.Duration](o)
		case identServerIdleTimeout{}:
			cfg.idleTimeout = option.MustGet[time.Duration](o)
		case identServerMaxConnections{}:
			cfg.maxConnections = option.MustGet[int](o)
		case identServerMaxConnsPerSource{}:
			cfg.maxConnsPerSource = option.MustGet[int](o)
		case identServerMaxConcurrentStreams{}:
			cfg.maxConcurrentStreams = option.MustGet[uint32](o)
		}
	}
	if cfg.tlsConfig == nil {
		return nil, ErrTLSConfigRequired
	}
	tc := cfg.tlsConfig.Clone()
	if tc.MinVersion == 0 {
		tc.MinVersion = tls.VersionTLS13
	}
	// RFC 8484 inherits HTTPS's TLS 1.2 floor; enforce regardless of caller
	// config so a copy-pasted tls.Config can't silently downgrade.
	if tc.MinVersion < tls.VersionTLS12 {
		tc.MinVersion = tls.VersionTLS12
	}
	// Advertise both HTTP/2 and HTTP/1.1 — RFC 8484 mandates HTTP/2
	// support but real-world clients still negotiate 1.1 frequently.
	for _, p := range []string{"h2", "http/1.1"} {
		if !slices.Contains(tc.NextProtos, p) {
			tc.NextProtos = append(tc.NextProtos, p)
		}
	}
	cfg.tlsConfig = tc
	return &Server{addr: addr, handler: h, cfg: cfg}, nil
}

// Run binds a fresh TCP socket, wraps it with TLS, and serves
// HTTP/2 + HTTP/1.1 DoH requests until ctx is cancelled.
func (s *Server) Run(ctx context.Context) (*Controller, error) {
	ln, err := net.Listen("tcp", s.addr.String()) //nolint:noctx // socket lifetime is bound to Run's ctx
	if err != nil {
		return nil, fmt.Errorf("doh: listen %s: %w", s.addr, err)
	}
	la, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		_ = ln.Close()
		return nil, fmt.Errorf("doh: listen %s: unexpected addr type %T", s.addr, ln.Addr())
	}
	bound := netip.AddrPortFrom(la.AddrPort().Addr(), uint16(la.Port))

	if s.cfg.maxConnections > 0 || s.cfg.maxConnsPerSource > 0 {
		// limitListener gracefully handles either knob being zero.
		// We always wrap when the per-source cap is set so the
		// per-source bookkeeping fires; the global cap defaults to
		// math.MaxInt32 in that case to keep behaviour identical.
		globalCap := s.cfg.maxConnections
		if globalCap <= 0 {
			globalCap = 1 << 30
		}
		ln = newLimitListener(ln, globalCap, s.cfg.maxConnsPerSource)
	}

	mux := http.NewServeMux()
	mux.Handle(s.cfg.path, NewHandler(s.handler, WithHandlerMaxRequestBytes(s.cfg.maxRequestBytes)))

	hs := &http.Server{
		Handler:           mux,
		TLSConfig:         s.cfg.tlsConfig,
		ReadHeaderTimeout: s.cfg.readHeaderTimeout,
		ReadTimeout:       s.cfg.readTimeout,
		WriteTimeout:      s.cfg.writeTimeout,
		IdleTimeout:       s.cfg.idleTimeout,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	if s.cfg.maxConcurrentStreams > 0 {
		if err := http2.ConfigureServer(hs, &http2.Server{
			MaxConcurrentStreams: s.cfg.maxConcurrentStreams,
		}); err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("doh: configure http2: %w", err)
		}
	}

	ctrl := &Controller{Core: serverctl.New(bound)}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(shutdownCtx)
	}()
	go func() {
		defer ctrl.CloseDone()
		err := hs.ServeTLS(ln, "", "")
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			ctrl.SetErr(fmt.Errorf("doh: serve: %w", err))
		}
	}()
	return ctrl, nil
}

// Controller is the runtime handle returned by [Server.Run]. It
// embeds [serverctl.Core] (Addr / Done / Err / Wait); doh-specific
// runtime queries belong on this type.
type Controller struct {
	serverctl.Core
}
