package dnscrypt

import "time"

// Option configures an Exchanger.
type Option interface{ applyDNSCrypt(*config) }

type optionFunc func(*config)

func (f optionFunc) applyDNSCrypt(c *config) { f(c) }

type config struct {
	timeout time.Duration
}

// WithTimeout sets the per-exchange timeout when ctx has no deadline.
func WithTimeout(d time.Duration) Option {
	return optionFunc(func(c *config) { c.timeout = d })
}
