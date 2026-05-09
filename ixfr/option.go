package ixfr

import (
	"time"

	"github.com/lestrrat-go/acidns/tsig"
)

// Option configures a Start call.
type Option interface{ applyIXFR(*config) }

type optionFunc func(*config)

func (f optionFunc) applyIXFR(c *config) { f(c) }

type config struct {
	timeout   time.Duration
	tsigKey   *tsig.Key
	tsigNow   func() time.Time
	tsigFudge time.Duration
}

// WithTimeout sets the per-stream-message read timeout used when ctx has
// no deadline. Defaults to 30 seconds.
func WithTimeout(d time.Duration) Option {
	return optionFunc(func(c *config) { c.timeout = d })
}

// WithTSIGKey signs the outgoing IXFR query with the supplied key
// (RFC 8945) and verifies signed envelopes streamed back from the
// server. See [github.com/lestrrat-go/acidns/axfr.WithTSIGKey] for
// the multi-message verification model used here.
func WithTSIGKey(key *tsig.Key) Option {
	return optionFunc(func(c *config) { c.tsigKey = key })
}

// WithTSIGFudge sets the clock-skew window. Defaults to 5 minutes.
// Only takes effect with [WithTSIGKey].
func WithTSIGFudge(d time.Duration) Option {
	return optionFunc(func(c *config) { c.tsigFudge = d })
}

// WithTSIGClock injects a clock for tests. Only takes effect with
// [WithTSIGKey].
func WithTSIGClock(now func() time.Time) Option {
	return optionFunc(func(c *config) { c.tsigNow = now })
}
