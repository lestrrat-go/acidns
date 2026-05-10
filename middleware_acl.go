package acidns

// ACL middleware: a Handler middleware that filters queries by source
// address, returning REFUSED to clients outside the configured ACL.
//
// Apply on top of any Handler:
//
//	srv, _ := acidns.NewUDPServer(addr, acidns.NewACL(inner,
//	    acl.WithACLAllow(netip.MustParsePrefix("10.0.0.0/8")),
//	))
//	ctrl, _ := srv.Run(ctx)
//
// # Default policy
//
// NewACL requires at least one of WithACLAllow or WithACLDeny — a
// rule-less ACL would be silently allow-all and would mask a
// "tighten access by adding the middleware" misconfiguration.
// Construction without rules returns [ErrACLNoRules].

import (
	"context"
	"errors"
	"net/netip"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/option/v3"
)

// ErrACLNoRules is returned by NewACL when neither WithACLAllow nor
// WithACLDeny is supplied. Without rules, the ACL is silently
// allow-all — a misconfiguration that adding the middleware "for
// security" would mask. Refuse the construction instead so the
// operator catches the omission immediately.
var ErrACLNoRules = errors.New("acidns: NewACL requires at least one of WithACLAllow / WithACLDeny")

// ACLOption configures the ACL.
type ACLOption interface {
	option.Interface
	aclOption()
}

type aclOption struct{ option.Interface }

func (aclOption) aclOption() {}

type aclConfig struct {
	allow      []netip.Prefix
	deny       []netip.Prefix
	dropDenied bool
}

type identACLAllow struct{}
type identACLDeny struct{}
type identACLDropDenied struct{}

// WithACLAllow sets the explicit allow list. If non-empty, queries from any
// other source are refused.
func WithACLAllow(prefixes ...netip.Prefix) ACLOption {
	return aclOption{option.New(identACLAllow{}, prefixes)}
}

// WithACLDeny adds prefixes that are unconditionally refused. Deny is
// evaluated before allow.
func WithACLDeny(prefixes ...netip.Prefix) ACLOption {
	return aclOption{option.New(identACLDeny{}, prefixes)}
}

// WithACLDropDenied controls whether denied requests are silently
// dropped (true) or answered with REFUSED (false). A REFUSED reply is
// an EDNS-shaped echo of the question and gives an off-path attacker
// a small (~1.4×) amplification primitive against any spoofed source
// IP. On a public UDP listener — where the source address is
// unverifiable until cookies or path validation kicks in — drop-mode
// keeps the listener's amplification factor below 1×.
//
// Default: true (drop). The default targets the riskier deployment
// (internet-exposed UDP) so that the safe behaviour is the one a
// caller gets without thinking. Pass WithACLDropDenied(false) behind
// a path-validated gate (TCP, DoT, DoH, DoQ) where REFUSED's signal
// value to a legitimate misconfigured client outweighs the
// amplification cost.
func WithACLDropDenied(drop bool) ACLOption {
	return aclOption{option.New(identACLDropDenied{}, drop)}
}

type acl struct {
	inner      Handler
	allow      []netip.Prefix
	deny       []netip.Prefix
	dropDenied bool
}

// NewACL returns a Handler that applies the configured ACL before
// delegating to inner. At least one of [WithACLAllow] or
// [WithACLDeny] is required; otherwise [ErrACLNoRules] is returned.
func NewACL(inner Handler, opts ...ACLOption) (Handler, error) {
	c := &aclConfig{dropDenied: true}
	for _, o := range opts {
		switch o.Ident() {
		case identACLAllow{}:
			c.allow = append(c.allow, option.MustGet[[]netip.Prefix](o)...)
		case identACLDeny{}:
			c.deny = append(c.deny, option.MustGet[[]netip.Prefix](o)...)
		case identACLDropDenied{}:
			c.dropDenied = option.MustGet[bool](o)
		}
	}
	if len(c.allow) == 0 && len(c.deny) == 0 {
		return nil, ErrACLNoRules
	}
	return &acl{inner: inner, allow: c.allow, deny: c.deny, dropDenied: c.dropDenied}, nil
}

func (a *acl) ServeDNS(ctx context.Context, w ResponseWriter, q wire.Message) {
	// Unmap so a v4-mapped peer (typical for IPv4 traffic on a dual-stack
	// `::` listener) is matched against the operator's IPv4 prefixes, not
	// against `::ffff:0:0/96`. Without Unmap, an `WithACLAllow(10.0.0.0/24)`
	// silently rejects every IPv4 client.
	src := w.RemoteAddr().Addr().Unmap()
	if !a.permit(src) {
		if a.dropDenied {
			return
		}
		a.refuse(w, q)
		return
	}
	a.inner.ServeDNS(ctx, w, q)
}

func (a *acl) permit(src netip.Addr) bool {
	for _, p := range a.deny {
		if p.Contains(src) {
			return false
		}
	}
	if len(a.allow) == 0 {
		return true
	}
	for _, p := range a.allow {
		if p.Contains(src) {
			return true
		}
	}
	return false
}

func (a *acl) refuse(w ResponseWriter, q wire.Message) {
	b := wire.NewMessageBuilder().
		ID(q.ID()).
		Response(true).
		RecursionDesired(q.Flags().RecursionDesired()).
		RCODE(wire.RCODERefused)
	if len(q.Questions()) > 0 {
		b = b.Question(q.Questions()[0])
	}
	resp, err := b.Build()
	if err != nil {
		// Builder failure is implausible for a fixed-shape REFUSED;
		// fall back to a header-only SERVFAIL so the peer at least
		// sees something rather than a silent drop.
		fb, ferr := wire.NewMessageBuilder().ID(q.ID()).Response(true).RCODE(wire.RCODEServFail).Build()
		if ferr == nil {
			_ = w.WriteMsg(fb)
		}
		return
	}
	_ = w.WriteMsg(resp)
}
