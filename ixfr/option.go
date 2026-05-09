package ixfr

import (
	"time"

	"github.com/lestrrat-go/acidns/tsig"
	"github.com/lestrrat-go/option/v3"
)

// Option configures a Start call.
type Option interface {
	option.Interface
	ixfrOption()
}

type ixfrOption struct{ option.Interface }

func (ixfrOption) ixfrOption() {}

type config struct {
	timeout   time.Duration
	tsigKey   *tsig.Key
	tsigNow   func() time.Time
	tsigFudge time.Duration
}

type identTimeout struct{}
type identTSIGKey struct{}
type identTSIGFudge struct{}
type identTSIGClock struct{}

// WithTimeout sets the per-stream-message read timeout used when ctx has
// no deadline. Defaults to 30 seconds.
func WithTimeout(d time.Duration) Option {
	return ixfrOption{option.New(identTimeout{}, d)}
}

// WithTSIGKey signs the outgoing IXFR query with the supplied key
// (RFC 8945) and verifies signed envelopes streamed back from the
// server. See [github.com/lestrrat-go/acidns/axfr.WithTSIGKey] for
// the multi-message verification model used here.
func WithTSIGKey(key *tsig.Key) Option {
	return ixfrOption{option.New(identTSIGKey{}, key)}
}

// WithTSIGFudge sets the clock-skew window. Defaults to 5 minutes.
// Only takes effect with [WithTSIGKey].
func WithTSIGFudge(d time.Duration) Option {
	return ixfrOption{option.New(identTSIGFudge{}, d)}
}

// WithTSIGClock injects a clock for tests. Only takes effect with
// [WithTSIGKey].
func WithTSIGClock(now func() time.Time) Option {
	return ixfrOption{option.New(identTSIGClock{}, now)}
}
