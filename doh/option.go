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

// WithPadding toggles RFC 8467 §4.1 block-padding. Default is true:
// outgoing queries are padded to a 128-byte boundary so the encrypted
// HTTP/2 frame's size cannot leak the queried name. Pass false to
// disable padding.
func WithPadding(v bool) Option {
	return optionFunc(func(c *config) { c.padding = v })
}
