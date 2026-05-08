// Package doh implements DNS over HTTPS (RFC 8484).
//
// The Exchange method always uses POST with content type
// application/dns-message; GET (base64url-encoded query) is supported via
// WithMethod for caches that prefer it.
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

// Option configures a DoH Exchanger.
type Option interface{ applyDoH(*config) }

type optionFunc func(*config)

func (f optionFunc) applyDoH(c *config) { f(c) }

type config struct {
	client    *http.Client
	method    Method
	userAgent string
}

// WithHTTPClient overrides the default *http.Client.
func WithHTTPClient(hc *http.Client) Option {
	return optionFunc(func(c *config) { c.client = hc })
}

// WithMethod selects POST (default) or GET.
func WithMethod(m Method) Option {
	return optionFunc(func(c *config) { c.method = m })
}

// WithUserAgent sets the User-Agent header on outgoing requests.
func WithUserAgent(ua string) Option {
	return optionFunc(func(c *config) { c.userAgent = ua })
}

type exchanger struct {
	endpoint  string
	client    *http.Client
	method    Method
	userAgent string
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
	c := config{client: http.DefaultClient, method: MethodPOST, userAgent: "acidns-doh/0.1"}
	for _, o := range opts {
		o.applyDoH(&c)
	}
	if c.client == nil {
		c.client = http.DefaultClient
	}
	return &exchanger{endpoint: endpoint, client: c.client, method: c.method, userAgent: c.userAgent}, nil
}

func (e *exchanger) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
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
		return nil, fmt.Errorf("doh: http %d: %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" && ct != contentType {
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
