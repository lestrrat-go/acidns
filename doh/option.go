package doh

import "net/http"

// Option configures a DoH Exchanger.
type Option interface{ applyDoH(*config) }

type optionFunc func(*config)

func (f optionFunc) applyDoH(c *config) { f(c) }

type config struct {
	client    *http.Client
	method    Method
	userAgent string
	padding   bool
	insecure  bool
}

// WithHTTPClient overrides the default *http.Client.
//
// The supplied client's Transport is inspected at construction. When
// it is an *http.Transport, [New] scrubs two footguns on a private
// copy used internally:
//
//   - Proxy is forced to nil. The default-client construction
//     deliberately omits ProxyFromEnvironment so a stub-resolver caller
//     does not silently route every DoH query (and the queried name)
//     through whatever $HTTPS_PROXY points at; the same scrub applies
//     to caller-supplied clients.
//   - TLSClientConfig.InsecureSkipVerify=true is rejected: [New]
//     returns an error instead of silently disabling certificate
//     verification.
//
// Callers needing a proxy or custom verification logic should supply
// a Transport whose type is not *http.Transport (e.g. a wrapper).
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

// WithPadding toggles RFC 8467 §4.1 block-padding. Default is true:
// outgoing queries are padded to a 128-byte boundary so the encrypted
// HTTP/2 frame's size cannot leak the queried name. Pass false to
// disable padding.
func WithPadding(v bool) Option {
	return optionFunc(func(c *config) { c.padding = v })
}

// WithInsecure permits a plaintext "http://" endpoint. By default
// [New] refuses non-HTTPS schemes — DoH (RFC 8484) is meaningful only
// over a TLS-protected channel, and silently downgrading to HTTP would
// defeat the privacy goal. Use this only for tests against a local
// loopback server (e.g. httptest.NewServer). Pass true to allow
// plaintext, false to enforce HTTPS (the default).
func WithInsecure(v bool) Option {
	return optionFunc(func(c *config) { c.insecure = v })
}
