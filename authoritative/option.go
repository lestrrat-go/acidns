package authoritative

import (
	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/zonefile"
)

// Option configures an Authoritative at construction.
type Option interface{ applyAuth(*config) }

type optionFunc func(*config)

func (f optionFunc) applyAuth(c *config) { f(c) }

type config struct {
	zones         []zonefile.Zone
	notifyHandler NotifyHandler
	updatePolicy  UpdatePolicy
}

// UpdatePolicy decides whether an inbound RFC 2136 UPDATE may proceed.
// It is invoked after the request has been parsed but before any zone
// state changes; return true to admit the update, false to respond with
// REFUSED.
//
// A nil policy means the server refuses all UPDATEs — callers that want
// to accept dynamic updates MUST install a policy explicitly. A typical
// implementation runs [tsig.VerifyMAC] against a configured keyring
// before returning true (RFC 3007).
type UpdatePolicy func(w acidns.ResponseWriter, q wire.Message) bool

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

// WithUpdatePolicy installs the gate that admits inbound UPDATE
// requests. Without this option (the default) every UPDATE is refused
// with REFUSED — accepting unauthenticated updates is unsafe in
// production, so the caller must opt in deliberately.
//
// The policy is responsible for any TSIG/SIG(0) verification it wants
// to enforce; the authoritative server intentionally does not bake in
// a single auth scheme.
func WithUpdatePolicy(p UpdatePolicy) Option {
	return optionFunc(func(c *config) { c.updatePolicy = p })
}
