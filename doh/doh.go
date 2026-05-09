// Package doh implements DNS over HTTPS (RFC 8484) — DNS messages
// carried inside HTTP/2 (or HTTP/1.1) requests with content type
// application/dns-message. Use it for stub resolvers in environments
// where DoT is blocked but HTTPS is allowed, or as the upstream of a
// caching forwarder.
//
// # Method
//
// Exchange defaults to POST: a single HTTP request carries the wire
// query in its body and receives the wire response in the body of the
// 200 reply. WithMethod(MethodGET) selects RFC 8484 §4.1's
// base64url-encoded GET form, which interacts better with caching
// proxies but exposes the query in URL logs.
//
// # HTTP transport
//
// WithHTTPClient overrides the default *http.Client so callers can
// pass their own connection pool, dialer, or TLS config (including
// HTTP/3 once net/http supports it natively). WithUserAgent sets a
// custom User-Agent header.
//
// # Padding
//
// Outgoing queries are padded to a 128-byte boundary per RFC 8467 §4.1
// before HTTP/2 framing, so the encrypted frame size cannot leak the
// queried name. Disable with WithPadding(false).
//
// # Errors
//
// Non-200 HTTP responses surface as *HTTPStatusError, which carries
// the status code, status line, and (capped) response body so callers
// can log the upstream's diagnostic text without re-issuing the
// request. errors.Is matches by exact StatusCode; .Class() returns the
// 1/2/3/4/5 class for "any 5xx" branching.
package doh

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
)

const contentType = "application/dns-message"

// maxResponseBytes caps the DoH response body. RFC 8484 carries one
// DNS message, whose wire form is bounded by the 16-bit length field
// plus a small slack for HTTP framing variations. A hostile (or
// compromised) endpoint could otherwise stream gigabytes through
// io.ReadAll before wire.Unmarshal rejects the result.
const maxResponseBytes = 64 * 1024

// defaultClient is used when the caller doesn't supply WithHTTPClient.
// http.DefaultClient is unsuitable: it has no timeout and is shared
// process-wide, so a misbehaving endpoint can hang queries indefinitely
// and contend with unrelated HTTP code in the same binary.
//
// CheckRedirect returns http.ErrUseLastResponse so the client surfaces
// the 3xx as the HTTP response rather than auto-following it. A hostile
// or misconfigured DoH endpoint that 302s to http:// would otherwise
// bypass the scheme guard at New, since the redirect is followed by
// the underlying http.Client and not re-validated. RFC 8484 has no
// notion of redirected DoH; a 3xx is itself a protocol violation.
func defaultClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			// Proxy is intentionally nil. http.ProxyFromEnvironment
			// would honour $HTTPS_PROXY / $HTTP_PROXY and silently
			// route every DoH query (including the queried name)
			// through whatever the env points at — surprising for
			// a stub-resolver caller. Operators who want a proxy
			// should pass a custom *http.Client via [WithClient].
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          16,
			MaxIdleConnsPerHost:   4,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// Method selects the HTTP method used for queries.
type Method string

const (
	MethodPOST Method = http.MethodPost
	MethodGET  Method = http.MethodGet
)

type exchanger struct {
	endpoint  string
	client    *http.Client
	method    Method
	userAgent string
	padding   bool
}

// New returns an Exchanger that talks DoH to the given endpoint URL
// (e.g. "https://cloudflare-dns.com/dns-query").
func New(endpoint string, opts ...Option) (acidns.Exchanger, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("doh: invalid endpoint: %w", err)
	}
	c := config{method: MethodPOST, userAgent: "acidns-doh/0.1", padding: true}
	for _, o := range opts {
		o.applyDoH(&c)
	}
	switch u.Scheme {
	case "https":
		// the only real DoH transport
	case "http":
		if !c.insecure {
			return nil, fmt.Errorf("doh: refusing plaintext http:// endpoint; use https:// or WithInsecure() (test loopback only)")
		}
	default:
		return nil, fmt.Errorf("doh: endpoint scheme must be https (or http with WithInsecure)")
	}
	if c.client == nil {
		c.client = defaultClient()
	}
	// Force the no-redirect contract regardless of what the caller
	// supplied. RFC 8484 has no notion of redirected DoH; a 3xx is
	// a protocol violation by the server, and silently following it
	// (which any caller-supplied http.Client would do unless they
	// explicitly disabled redirects) bypasses the scheme guard at
	// New that refuses http:// endpoints. Shallow-copy so we don't
	// mutate the caller's client.
	clientCopy := *c.client
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &exchanger{endpoint: endpoint, client: &clientCopy, method: c.method, userAgent: c.userAgent, padding: c.padding}, nil
}

func (e *exchanger) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
	if e.padding {
		q = wire.PadEncrypted(q)
	}
	msg, err := wire.Marshal(q)
	if err != nil {
		return nil, fmt.Errorf("doh: marshal: %w", err)
	}

	req, err := e.buildRequest(ctx, msg)
	if err != nil {
		return nil, err
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh: request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, &HTTPStatusError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Body:       body,
		}
	}
	// RFC 8484 §6: a DoH server MUST set Content-Type to
	// application/dns-message. Treat both a missing and a wrong header
	// as a hard error — a server that omits Content-Type is either
	// misbehaving or proxying through middleware that strips it, and
	// trusting whatever bytes arrived as a DNS message in either case
	// would launder the protocol violation downstream.
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		return nil, fmt.Errorf("doh: response missing Content-Type header (RFC 8484 §6 requires %q)", contentType)
	}
	if ct != contentType {
		return nil, fmt.Errorf("doh: unexpected content type %q", ct)
	}

	// If the server advertised Content-Length, refuse before reading
	// any body when it claims more than the cap. Without this an
	// upstream that lies about its body size could force us into a
	// 64 KiB allocation per query even though we'd reject the body
	// shortly after.
	if cl := resp.ContentLength; cl > maxResponseBytes {
		return nil, fmt.Errorf("doh: Content-Length %d exceeds %d byte cap", cl, maxResponseBytes)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("doh: read body: %w", err)
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("doh: response body exceeds %d byte cap", maxResponseBytes)
	}
	m, err := wire.Unmarshal(body)
	if err != nil {
		return nil, fmt.Errorf("doh: unmarshal: %w", err)
	}
	if m.ID() != q.ID() {
		return nil, fmt.Errorf("doh: id mismatch")
	}
	if !wire.QuestionsMatch(q, m) {
		return nil, fmt.Errorf("doh: response question does not match request")
	}
	return m, nil
}

func (e *exchanger) buildRequest(ctx context.Context, msg []byte) (*http.Request, error) {
	switch e.method {
	case MethodGET:
		// RFC 8484 §4.1: dns parameter, base64url-encoded, no padding.
		dnsParam := base64.RawURLEncoding.EncodeToString(msg)
		u, _ := url.Parse(e.endpoint)
		qry := u.Query()
		qry.Set("dns", dnsParam)
		u.RawQuery = qry.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", contentType)
		if e.userAgent != "" {
			req.Header.Set("User-Agent", e.userAgent)
		}
		return req, nil
	default:
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, bytes.NewReader(msg))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("Accept", contentType)
		if e.userAgent != "" {
			req.Header.Set("User-Agent", e.userAgent)
		}
		return req, nil
	}
}
