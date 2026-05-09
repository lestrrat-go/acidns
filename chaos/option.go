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
type identNext struct{}

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

// WithNext sets the Handler to delegate to when the query is not a CHAOS
// identity query handled by this Handler. Without WithNext, non-matching
// queries receive a REFUSED response so this handler can stand alone.
func WithNext(h acidns.Handler) Option {
	return chaosOption{option.New(identNext{}, h)}
}
