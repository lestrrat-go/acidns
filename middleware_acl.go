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
// An ACL constructed with NO options (no allow list and no deny list)
// is allow-all: every source is permitted. This makes NewACL safely
// composable into a middleware chain ahead of policy decisions
// without changing observed behaviour, but means a misconfigured
// caller that thinks it's tightening access by adding the middleware
// in isolation will get no protection. Always pair NewACL with at
// least one of WithACLAllow / WithACLDeny in production.

import (
	"context"
	"net/netip"

	"github.com/lestrrat-go/acidns/wire"
)

// ACLOption configures the ACL.
type ACLOption interface{ applyACL(*aclConfig) }

type aclOptionFunc func(*aclConfig)

func (f aclOptionFunc) applyACL(c *aclConfig) { f(c) }

type aclConfig struct {
	allow []netip.Prefix
	deny  []netip.Prefix
}

// WithACLAllow sets the explicit allow list. If non-empty, queries from any
// other source are refused.
func WithACLAllow(prefixes ...netip.Prefix) ACLOption {
	return aclOptionFunc(func(c *aclConfig) { c.allow = append(c.allow, prefixes...) })
}

// WithACLDeny adds prefixes that are unconditionally refused. Deny is
// evaluated before allow.
func WithACLDeny(prefixes ...netip.Prefix) ACLOption {
	return aclOptionFunc(func(c *aclConfig) { c.deny = append(c.deny, prefixes...) })
}

type acl struct {
	inner Handler
	allow []netip.Prefix
	deny  []netip.Prefix
}

// NewACL returns a Handler that applies the configured ACL before delegating
// to inner.
func NewACL(inner Handler, opts ...ACLOption) Handler {
	c := &aclConfig{}
	for _, o := range opts {
		o.applyACL(c)
	}
	return &acl{inner: inner, allow: c.allow, deny: c.deny}
}

func (a *acl) ServeDNS(ctx context.Context, w ResponseWriter, q wire.Message) {
	src := w.RemoteAddr().Addr()
	if !a.permit(src) {
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
	b := wire.NewBuilder().
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
		fb, ferr := wire.NewBuilder().ID(q.ID()).Response(true).RCODE(wire.RCODEServFail).Build()
		if ferr == nil {
			_ = w.WriteMsg(fb)
		}
		return
	}
	_ = w.WriteMsg(resp)
}
