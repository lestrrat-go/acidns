package zonefile

import (
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/option/v3"
)

// Option configures a parse.
type Option interface {
	option.Interface
	zonefileOption()
}

type zonefileOption struct{ option.Interface }

func (zonefileOption) zonefileOption() {}

type config struct {
	origin     wire.Name
	defaultTTL int64 // seconds, -1 = unset
}

type identOrigin struct{}
type identDefaultTTL struct{}

// WithOrigin sets the initial origin used until $ORIGIN appears.
func WithOrigin(n wire.Name) Option {
	return zonefileOption{option.New(identOrigin{}, n)}
}

// WithDefaultTTL sets the initial TTL used until $TTL appears.
func WithDefaultTTL(seconds int) Option {
	return zonefileOption{option.New(identDefaultTTL{}, seconds)}
}
