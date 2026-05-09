package axfr

import (
	"time"

	"github.com/lestrrat-go/acidns/tsig"
	"github.com/lestrrat-go/option/v3"
)

// Option configures a Start call.
type Option interface {
	option.Interface
	axfrOption()
}

type axfrOption struct{ option.Interface }

func (axfrOption) axfrOption() {}

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
	return axfrOption{option.New(identTimeout{}, d)}
}

// WithTSIGKey signs the outgoing AXFR query with the supplied key
// (RFC 8945 + RFC 5936 §4.2.2) and verifies signed envelopes streamed
// back from the server.
//
// Per RFC 8945 §5.3.1/§5.3.2, AXFR responses use multi-message TSIG
// chaining where signed envelopes carry MACs that bind to the previous
// MAC. This implementation performs a simplified verification: it
// requires the FIRST envelope to be signed (per §5.3.1) and verifies
// that signature; intermediate unsigned envelopes are tolerated; the
// FINAL (closing-SOA) envelope is also verified if signed. The chain
// MAC is threaded through across all signed envelopes so out-of-order
// or tampered envelopes fail verification at the next signed boundary.
func WithTSIGKey(key *tsig.Key) Option {
	return axfrOption{option.New(identTSIGKey{}, key)}
}

// WithTSIGFudge sets the clock-skew window. Defaults to 5 minutes.
// Only takes effect with [WithTSIGKey].
func WithTSIGFudge(d time.Duration) Option {
	return axfrOption{option.New(identTSIGFudge{}, d)}
}

// WithTSIGClock injects a clock for tests. Only takes effect with
// [WithTSIGKey].
func WithTSIGClock(now func() time.Time) Option {
	return axfrOption{option.New(identTSIGClock{}, now)}
}
