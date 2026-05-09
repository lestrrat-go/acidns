package notify

import (
	"time"

	"github.com/lestrrat-go/acidns/tsig"
	"github.com/lestrrat-go/acidns/wire/rdata"
)

// Option configures a Send call.
type Option interface{ applyNotify(*config) }

type optionFunc func(*config)

func (f optionFunc) applyNotify(c *config) { f(c) }

type config struct {
	timeout  time.Duration
	soa      rdata.SOA
	hasSOA   bool
	tsigKey  *tsig.Key
	tsigNow  func() time.Time
	tsigFudge time.Duration
}

// WithTimeout sets the per-secondary timeout when ctx has no deadline.
// Defaults to 5 seconds.
func WithTimeout(d time.Duration) Option {
	return optionFunc(func(c *config) { c.timeout = d })
}

// WithSOA includes the new SOA in the answer section (RFC 1996 §3.7).
// Some secondaries skip the follow-up SOA query when the new SOA is
// piggy-backed on the NOTIFY.
func WithSOA(soa rdata.SOA) Option {
	return optionFunc(func(c *config) {
		c.soa = soa
		c.hasSOA = true
	})
}

// WithTSIGKey signs outgoing NOTIFYs with the supplied key (RFC 8945).
// When set, the response's TSIG MAC — if any — is verified against the
// request's signature. A verification failure surfaces as
// [ErrTSIGVerify] wrapping the underlying tsig error.
func WithTSIGKey(key *tsig.Key) Option {
	return optionFunc(func(c *config) { c.tsigKey = key })
}

// WithTSIGFudge sets the clock-skew window the receiver tolerates.
// Defaults to 5 minutes. Only takes effect when [WithTSIGKey] is set.
func WithTSIGFudge(d time.Duration) Option {
	return optionFunc(func(c *config) { c.tsigFudge = d })
}

// WithTSIGClock injects a clock for tests. Only takes effect when
// [WithTSIGKey] is set.
func WithTSIGClock(now func() time.Time) Option {
	return optionFunc(func(c *config) { c.tsigNow = now })
}
