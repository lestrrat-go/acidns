package chaos

import (
	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/option/v3"
)

// Option customises the chaos handler.
type Option interface {
	option.Interface
	chaosOption()
}

type chaosOption struct{ option.Interface }

func (chaosOption) chaosOption() {}

type config struct {
	id      string
	version string
	next    acidns.Handler
}

type identIdentifier struct{}
type identVersion struct{}

// WithIdentifier sets the response for id.server. and hostname.bind.
// queries. Empty string disables matching for those names.
func WithIdentifier(id string) Option {
	return chaosOption{option.New(identIdentifier{}, id)}
}

// WithVersion sets the response for version.server. and version.bind.
// queries. Empty string disables matching for those names.
func WithVersion(version string) Option {
	return chaosOption{option.New(identVersion{}, version)}
}
