package acidns

import (
	"context"
	"net/netip"
)

// ctxServerSinkKey is the context-value key under which Resolve installs a
// per-call sink for leaf Exchangers to report which immediate upstream they
// contacted. The Resolver reads the sink after Exchange returns and stamps
// the addr onto Answer.server (success/RCODE path) or onto a *serverErr
// (network-error path). The Lookup* family reads it back via [errors.As] to
// populate [net.DNSError.Server].
//
// The sink is concurrency-safe by construction: every Resolver.resolve call
// derives a fresh context with its own *netip.AddrPort, so concurrent
// resolves (e.g. parallel A/AAAA in [LookupHost]) cannot race on it.
type ctxServerSinkKey struct{}

func withServerSink(ctx context.Context, sink *netip.AddrPort) context.Context {
	return context.WithValue(ctx, ctxServerSinkKey{}, sink)
}

// SetExchangeServer is the hook a leaf [Exchanger] implementation calls on
// the success path of [Exchanger.Exchange] to report which immediate
// upstream produced the response. The host [Resolver] installs a sink in
// the context for the duration of the call and reads the most recent
// value back; that addr appears on the resulting Answer.Server() and, if
// the call eventually surfaces a [net.DNSError] via the [LookupHost]
// family, in [net.DNSError.Server].
//
// Calling without a sink in ctx is a no-op, so a stand-alone Exchanger
// used outside a Resolver still works.
//
// Composite Exchangers (failover, retry, TC=1→TCP fallback) propagate
// ctx unchanged to their inner exchanger and the sink naturally tracks
// whichever leaf served the response.
//
// Implementations in this module set the sink on success only. Failures
// without a known peer (DNS resolution of a hostname-form server,
// dial errors that never picked an address) leave the sink unset; the
// resulting [net.DNSError.Server] is empty.
func SetExchangeServer(ctx context.Context, addr netip.AddrPort) {
	sink, _ := ctx.Value(ctxServerSinkKey{}).(*netip.AddrPort)
	if sink != nil {
		*sink = addr
	}
}

// serverErr wraps an Exchange error with the immediate upstream addr the
// failed call was made against. Internal — the Lookup* family reads it
// via [errors.As] on a private type assertion. Callers that need the
// addr in an exported form can read it off [net.DNSError.Server] once
// the error has been wrapped at the LookupX boundary.
//
//nolint:errname // unexported; the xxxError suffix lint targets public API.
type serverErr struct {
	addr netip.AddrPort
	err  error
}

func (e *serverErr) Error() string { return e.err.Error() }
func (e *serverErr) Unwrap() error { return e.err }
