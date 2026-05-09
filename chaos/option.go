package chaos

import "github.com/lestrrat-go/acidns"

// Option customises the chaos handler.
type Option interface {
	applyChaos(*config)
}

type optionFunc func(*config)

func (f optionFunc) applyChaos(c *config) { f(c) }

type config struct {
	id      string
	version string
	next    acidns.Handler
}

// WithIdentifier sets the response for id.server. and hostname.bind.
// queries. Empty string disables matching for those names.
func WithIdentifier(id string) Option {
	return optionFunc(func(c *config) { c.id = id })
}

// WithVersion sets the response for version.server. and version.bind.
// queries. Empty string disables matching for those names.
func WithVersion(version string) Option {
	return optionFunc(func(c *config) { c.version = version })
}

// WithNext sets the Handler to delegate to when the query is not a CHAOS
// identity query handled by this Handler. Without WithNext, non-matching
// queries receive a REFUSED response so this handler can stand alone.
func WithNext(h acidns.Handler) Option {
	return optionFunc(func(c *config) { c.next = h })
}
