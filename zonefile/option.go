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
	origin                wire.Name
	defaultTTL            int64 // seconds, -1 = unset
	maxGenerateIterations int
}

type identOrigin struct{}
type identDefaultTTL struct{}
type identGenerateMaxIterations struct{}

// WithOrigin sets the initial origin used until $ORIGIN appears.
func WithOrigin(n wire.Name) Option {
	return zonefileOption{option.New(identOrigin{}, n)}
}

// WithDefaultTTL sets the initial TTL used until $TTL appears.
func WithDefaultTTL(seconds int) Option {
	return zonefileOption{option.New(identDefaultTTL{}, seconds)}
}

// WithGenerateMaxIterations caps how many records a single $GENERATE
// directive may produce. Defaults to [DefaultGenerateMaxIterations]. A
// directive whose range exceeds the cap is rejected at parse time
// rather than partially expanded.
func WithGenerateMaxIterations(n int) Option {
	return zonefileOption{option.New(identGenerateMaxIterations{}, n)}
}
