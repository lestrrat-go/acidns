// Package recursive is an iterative DNS resolver. It walks from the
// root servers downward, following NS referrals (with glue or
// out-of-bailiwick recursion), CNAME chains, and lame-server detection.
// Optional DNSSEC validation is delegated to dnssec/validator.
//
// # Production features
//
//   - CNAME chain following with loop detection and depth cap.
//   - Lame delegation detection: REFUSED / SERVFAIL / no-answer servers
//     are marked failing and deprioritised.
//   - Per-server smoothed-RTT and failure-streak tracking; rankings
//     prefer fast and healthy upstreams.
//   - EDNS0 with TC=1 → TCP fall-back (DNS Flag Day 2020 buffer 1232).
//   - Optional DNSSEC validation via WithValidator: bogus answers map
//     to SERVFAIL with EDE 6 (DNSSEC Bogus); insecure / indeterminate
//     pass through unchanged.
//   - RFC 2308 §5 negative caching with SOA MINIMUM cap.
//
// # Deferred
//
//   - QNAME minimisation (RFC 9156).
//   - Aggressive NSEC caching (RFC 8198).
//   - Parallel A/AAAA address resolution for NS targets.
//   - Per-upstream rate limiting and priming refresh.
//
// # Composition
//
// recursive.Resolver satisfies acidns.Resolver. Drop it into any caller
// that takes that interface — the LookupHost / ResolveAs[T] helpers in
// the root acidns package, or as the upstream of a forward.Forwarder.
package recursive
