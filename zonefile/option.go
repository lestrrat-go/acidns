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
	source                string
	includeResolver       IncludeResolver
	maxIncludeDepth       int
}

type identOrigin struct{}
type identDefaultTTL struct{}
type identGenerateMaxIterations struct{}
type identSourceName struct{}
type identIncludeResolver struct{}
type identIncludeMaxDepth struct{}

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

// WithSourceName labels the top-level source in error messages and
// supplies the base path used by [IncludeResolver] implementations
// when resolving relative-path $INCLUDEs from the top file. Defaults
// to "" — errors fall back to "line N: ..." form and first-level
// includes resolve from the resolver's root.
func WithSourceName(name string) Option {
	return zonefileOption{option.New(identSourceName{}, name)}
}

// WithIncludeResolver enables $INCLUDE by supplying a resolver.
// Without one, encountering $INCLUDE returns a parse error.
func WithIncludeResolver(r IncludeResolver) Option {
	return zonefileOption{option.New(identIncludeResolver{}, r)}
}

// WithIncludeMaxDepth caps how deeply $INCLUDE may nest. Defaults
// to [DefaultIncludeMaxDepth]. The cap protects against include
// cycles and stack exhaustion.
func WithIncludeMaxDepth(n int) Option {
	return zonefileOption{option.New(identIncludeMaxDepth{}, n)}
}
