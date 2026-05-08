package ixfr

import "time"

// Option configures a Start call.
type Option interface{ applyIXFR(*config) }

type optionFunc func(*config)

func (f optionFunc) applyIXFR(c *config) { f(c) }

type config struct {
	timeout time.Duration
}

// WithTimeout sets the per-stream-message read timeout used when ctx has
// no deadline. Defaults to 30 seconds.
func WithTimeout(d time.Duration) Option {
	return optionFunc(func(c *config) { c.timeout = d })
}
