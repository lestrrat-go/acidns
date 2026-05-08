package zonefile

import "github.com/lestrrat-go/acidns/wire"

// Option configures a parse.
type Option interface{ applyZone(*config) }

type optionFunc func(*config)

func (f optionFunc) applyZone(c *config) { f(c) }

type config struct {
	origin     wire.Name
	defaultTTL int64 // seconds, -1 = unset
}

// WithOrigin sets the initial origin used until $ORIGIN appears.
func WithOrigin(n wire.Name) Option {
	return optionFunc(func(c *config) { c.origin = n })
}

// WithDefaultTTL sets the initial TTL used until $TTL appears.
func WithDefaultTTL(seconds int) Option {
	return optionFunc(func(c *config) { c.defaultTTL = int64(seconds) })
}
