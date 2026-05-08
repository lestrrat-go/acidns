package notify

import (
	"time"

	"github.com/lestrrat-go/acidns/wire/rdata"
)

// Option configures a Send call.
type Option interface{ applyNotify(*config) }

type optionFunc func(*config)

func (f optionFunc) applyNotify(c *config) { f(c) }

type config struct {
	timeout time.Duration
	soa     rdata.SOA
	hasSOA  bool
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
