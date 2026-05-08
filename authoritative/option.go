package authoritative

import "github.com/lestrrat-go/acidns/zonefile"

// Option configures an Authoritative at construction.
type Option interface{ applyAuth(*config) }

type optionFunc func(*config)

func (f optionFunc) applyAuth(c *config) { f(c) }

type config struct {
	zones         []zonefile.Zone
	notifyHandler NotifyHandler
}

// WithZone adds z to the server's zones.
func WithZone(z zonefile.Zone) Option {
	return optionFunc(func(c *config) { c.zones = append(c.zones, z) })
}

// WithNotifyHandler installs a callback that fires when an inbound
// NOTIFY arrives. Use this on a secondary to schedule an IXFR/AXFR
// fetch from the primary that sent the NOTIFY.
func WithNotifyHandler(h NotifyHandler) Option {
	return optionFunc(func(c *config) { c.notifyHandler = h })
}
