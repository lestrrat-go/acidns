// Package forward implements a caching DNS forwarder. A forward.Handler
// answers queries by relaying them to a configured upstream Exchanger
// (UDP-with-TCP-fallback, DoT, or any custom transport — DoH and DoQ
// are wired the same way through WithUpstream) and caches both
// positive and negative responses honoring per-record TTLs and RFC 2308
// SOA MINIMUM, with a hard cap on negative-cache lifetime.
//
// # Composition
//
// The forwarder is a Handler — drop it into a UDP and a TCP listener
// from the acidns root package to expose it on the network. It does
// not implement DNSSEC validation; if the upstream sets AD on the
// response, AD is propagated, otherwise it is cleared.
//
// # Cache
//
// The cache is a fixed-size LRU keyed by (qname, qtype, qclass). TTLs
// are clamped to [WithMinTTL, WithMaxTTL] for positive answers and
// capped at WithMaxNegativeTTL for NXDOMAIN / NoData; the latter
// follows RFC 2308 §5 by additionally capping at SOA MINIMUM. Cache
// freshness checks use the clock injected by WithClock (default
// time.Now).
//
// # Lifecycle
//
// Handler.Close() drops all cached entries and propagates Close to the
// upstream Exchanger when it implements io.Closer (e.g. a DoT
// keep-alive transport). Callers SHOULD stop sending queries through
// the handler before calling Close — in-flight ServeDNS goroutines
// continue using the now-closed upstream until they exit.
//
// # Observability
//
// WithLogger wires a *slog.Logger that emits one structured event per
// inbound query with the decision (cache_hit / forwarded / formerr /
// notimp / upstream_error), the qname, qtype, upstream, RCODE, and
// elapsed duration.
package forward
