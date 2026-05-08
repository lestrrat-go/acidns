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
	"net/http"
	"net/url"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
)

const contentType = "application/dns-message"

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
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("doh: endpoint scheme must be http(s)")
	}
	c := config{client: http.DefaultClient, method: MethodPOST, userAgent: "acidns-doh/0.1", padding: true}
	for _, o := range opts {
		o.applyDoH(&c)
	}
	if c.client == nil {
		c.client = http.DefaultClient
	}
	return &exchanger{endpoint: endpoint, client: c.client, method: c.method, userAgent: c.userAgent, padding: c.padding}, nil
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("doh: read body: %w", err)
	}
	m, err := wire.Unmarshal(body)
	if err != nil {
		return nil, fmt.Errorf("doh: unmarshal: %w", err)
	}
	if m.ID() != q.ID() {
		return nil, fmt.Errorf("doh: id mismatch")
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
