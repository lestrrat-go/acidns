package authoritative

import (
	"context"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/zonefile"
)

// Option configures an Authoritative at construction.
type Option interface{ applyAuth(*config) }

type optionFunc func(*config)

func (f optionFunc) applyAuth(c *config) { f(c) }

type config struct {
	zones             []zonefile.Zone
	notifyHandler     NotifyHandler
	notifyPolicy      NotifyPolicy
	maxNotifyInflight int
	axfrPolicy        AXFRPolicy
	updatePolicy      UpdatePolicy
	minimalANY        bool
}

// UpdatePolicy decides whether an inbound RFC 2136 UPDATE may proceed.
// It is invoked after the request has been parsed but before any zone
// state changes; return true to admit the update, false to respond with
// REFUSED.
//
// A nil policy means the server refuses all UPDATEs — callers that want
// to accept dynamic updates MUST install a policy explicitly. A typical
// implementation runs [tsig.VerifyMAC] against a configured keyring
// before returning true (RFC 3007). The raw on-the-wire request bytes
// (which TSIG signs over) are available via [acidns.RawRequest](ctx);
// re-marshalling q is not byte-stable and won't verify against a TSIG
// MAC produced by the originator.
type UpdatePolicy func(ctx context.Context, w acidns.ResponseWriter, q wire.Message) bool

// AXFRPolicy decides whether an inbound RFC 5936 AXFR (or RFC 1995
// IXFR which falls back to AXFR) may proceed. It is invoked after the
// per-zone authority check passes — i.e. only for zones this server
// owns — but before any records are transmitted. Return true to admit
// the transfer, false to respond with REFUSED.
//
// A nil policy means the server refuses all transfer requests; this
// is the default because zone transfers expose every record to the
// requester, including records that operators with split-horizon
// deployments do NOT want leaked off-net. Callers that want to permit
// transfers MUST install a policy explicitly. A typical implementation
// matches w.RemoteAddr() against an allow-list of secondaries, or
// runs [tsig.VerifyMAC] for authenticated transfers; the raw request
// bytes (signed by TSIG) are reachable via [acidns.RawRequest](ctx).
type AXFRPolicy func(ctx context.Context, w acidns.ResponseWriter, q wire.Message) bool

// NotifyPolicy decides whether an inbound RFC 1996 NOTIFY is honoured.
// It is invoked after the per-zone ownership check passes — i.e. only
// for zones this server owns — and before the ACK is queued or any
// installed [NotifyHandler] fires. Return true to ACK and (if a
// handler is installed) trigger the post-accept callback, false to
// respond with REFUSED and skip the handler.
//
// A nil policy means the server refuses every NOTIFY. NOTIFY is
// usually delivered from a known primary on a well-known socket, so
// admitting it from anywhere is a forge primitive that lets any peer
// trigger the handler (typically scheduling an IXFR/AXFR that opens
// a TCP connection to a primary the secondary already trusts). A
// typical policy matches w.RemoteAddr() against the configured
// primaries.
type NotifyPolicy func(ctx context.Context, w acidns.ResponseWriter, q wire.Message) bool

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

// WithAXFRPolicy installs the gate that admits inbound AXFR (and
// fallback IXFR) requests. Without this option (the default) every
// transfer is refused with REFUSED — see [AXFRPolicy] for the
// rationale.
func WithAXFRPolicy(p AXFRPolicy) Option {
	return optionFunc(func(c *config) { c.axfrPolicy = p })
}

// WithNotifyPolicy installs the gate that admits inbound NOTIFY
// requests. Without this option (the default) every NOTIFY is
// refused with REFUSED — see [NotifyPolicy] for the rationale.
func WithNotifyPolicy(p NotifyPolicy) Option {
	return optionFunc(func(c *config) { c.notifyPolicy = p })
}

// WithMinimalANY controls the QTYPE=ANY response shape. When true
// (the default), QTYPE=ANY queries receive a single synthetic HINFO
// record with CPU="RFC8482" and OS="" per RFC 8482 §4 — the canonical
// "minimal ANY" shape. When false, the server walks the zone and
// returns every record at the QNAME, matching the legacy behaviour.
//
// Minimal ANY is the safe default because QTYPE=ANY is a known
// amplification primitive: a small request elicits a large multi-RRset
// reply that an off-path attacker can spoof at any source IP. RFC 8482
// is the IETF response — a canonical short reply that breaks the
// amplification ratio while still letting RFC-aware clients recognise
// the answer as a deliberate minimal response (rather than a truncated
// or dropped one). Pass WithMinimalANY(false) only on closed networks
// where the diagnostic value of a full zone-walk reply outweighs the
// amplification risk.
func WithMinimalANY(v bool) Option {
	return optionFunc(func(c *config) { c.minimalANY = v })
}

// WithMaxNotifyInflight caps how many [NotifyHandler] goroutines may
// run concurrently. NOTIFY-driven IXFR/AXFR fetches typically block
// on network I/O for seconds; without a cap a NOTIFY storm (or a
// misbehaving primary) spawns an unbounded goroutine pool. Default
// 32; pass 0 to disable the cap entirely.
func WithMaxNotifyInflight(n int) Option {
	return optionFunc(func(c *config) { c.maxNotifyInflight = n })
}
