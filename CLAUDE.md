# acidns

Full-fledged DNS toolkit in Go. Module: `github.com/lestrrat-go/acidns`.

## Scope

- Wire-format DNS encoder/decoder (RFC 1035 + extensions: EDNS0, DNSSEC, modern RR types).
- Client: stub resolver, recursive resolver, transports (UDP, TCP, DoT, DoH, DoQ).
- Server: authoritative + recursive (later phase).
- Zones: parser/writer for RFC 1035 master files; programmatic zone manipulation (later phase).
- CLI utilities (later phase).

## Style — non-negotiable

Follows `lestrrat-go/jwx` and `lestrrat-go/helium` conventions.

- Public API surface = interfaces. Concrete types = unexported impls returned by constructors.
- Constructors take functional options: `New(...Option)`. Options live in `option.go` per package.
- Builders for compound objects: `pkg.NewXxxBuilder().A(...).B(...).Build() (Xxx, error)`.
- Strongly typed accessors. NEVER expose `interface{}` / `any` in public signatures unless genuinely polymorphic.
- Sub-packages by concern, not by layer. One responsibility per package.
- Errors: sentinel `var ErrXxx = errors.New(...)` for matchable conditions; wrap with `fmt.Errorf("...: %w", err)`.
- No init() side effects. No package-level mutable state.

## Layout

```
acidns/                root: top-level convenience re-exports only, no logic
  dnsmsg/              wire-format messages, headers, questions, RRs, EDNS0
    rrtype/            RR type + class constants
    rdata/             rdata codecs (one file per RR type)
    internal/wire/     low-level packer/unpacker (compression, bounds)
  dnsname/             domain name type + parsing/encoding
  dnssec/              DNSSEC verification primitives (KeyTag, Verify, VerifyDS)
  dnszone/             RFC 1035 §5 master-file parser + writer
  tsig/                RFC 8945 transaction signature
  dnsclient/           client-facing API (Resolver, Answer, options)
    axfr/              AXFR client
    ixfr/              IXFR client (incremental + AXFR-fallback)
    dnsupdate/         RFC 2136 client builder
    resolvconf/        /etc/resolv.conf parser
    transport/         transport interface + sub-packages
      udp/, tcp/, dot/, doh/, doq/
      internal/streamframe/
  dnsserver/           Handler / ResponseWriter framework
    authoritative/     master-file-backed authoritative server
    recursive/         iterative recursive resolver + cache
    acl/               source-based ACL middleware
    ratelimit/         per-source token-bucket middleware
  cmd/
    acidig/            dig-style CLI
    acidns-server/     authoritative / recursive / hybrid daemon
  examples/lookup/     minimal SDK usage example
```

## Supported RFCs

Verification status: **Implemented** (with tests), **Partial** (subset documented inline), **Out of scope** (mentioned for context, not in the codebase).

| RFC | Title | Status |
|-----|-------|--------|
| 1034 | Domain Names — Concepts and Facilities | Implemented (authoritative §4.3.2 lookup algorithm) |
| 1035 | Domain Names — Implementation and Specification | Implemented (wire format, name compression §4.1.4, master files §5, TCP framing §4.2.2) |
| 1982 | Serial Number Arithmetic | Implemented (used by IXFR comparison) |
| 1995 | Incremental Zone Transfer (IXFR) | Implemented client; server falls back to AXFR per §3 |
| 2136 | Dynamic Updates in the Domain Name System | Implemented (UPDATE opcode, prerequisites, add/delete RRset, delete record) |
| 2308 | Negative Caching of DNS Queries | Implemented (recursive cache caps at SOA MINIMUM per §5) |
| 3110 | RSA SIG/KEY Resource Records | Implemented (RSA pubkey wire format used by DNSSEC) |
| 3596 | DNS Extensions to Support IPv6 | Implemented (AAAA records) |
| 3597 | Handling of Unknown DNS RR Types | Implemented (TYPEnnn parsing, generic `\#` writer form) |
| 4034 | Resource Records for the DNS Security Extensions | Implemented (DNSKEY, RRSIG, NSEC; canonical form §6) |
| 4035 | Protocol Modifications for DNSSEC | Partial (verification primitives only — no chain-of-trust walker, no NSEC/NSEC3 negative-proof validation) |
| 4509 | Use of SHA-256 in DNSSEC Delegation Signer | Implemented (DS digest type 2) |
| 4592 | Role of the Wildcard Label in the DNS | Implemented (authoritative wildcard synthesis with closest-encloser semantics) |
| 5155 | DNSSEC Hashed Authenticated Denial of Existence | Partial (NSEC3 type encode/decode; validator does not yet consume) |
| 5702 | RSA/SHA-2 in DNSSEC | Implemented (RSASHA256, RSASHA512) |
| 5936 | DNS Zone Transfer Protocol (AXFR) | Implemented (single-message AXFR, server + client) |
| 6605 | Elliptic Curve Digital Signature Algorithm (DSA) for DNSSEC | Implemented (ECDSAP256SHA256, ECDSAP384SHA384) |
| 6891 | Extension Mechanisms for DNS (EDNS(0)) | Implemented (OPT pseudo-RR, UDP size, DO bit, extended RCODE) |
| 7766 | DNS Transport over TCP | Partial (server-side multi-query per connection + idle timeout; no client-side keepalive) |
| 7858 | DNS over Transport Layer Security (DoT) | Implemented |
| 8080 | Edwards-Curve DSA for DNSSEC | Implemented (Ed25519; Ed448 not yet) |
| 8484 | DNS Queries over HTTPS (DoH) | Implemented (POST + GET) |
| 8624 | DNSSEC Algorithm Implementation Requirements | Followed (modern algorithms covered; SHA-1 supported only where required) |
| 8659 | DNS Certification Authority Authorization (CAA) | Implemented |
| 8945 | Secret Key Transaction Authentication for DNS (TSIG) | Implemented (hmac-sha1/256/384/512; not yet auto-wired into AXFR/IXFR/UPDATE clients) |
| 9250 | DNS over Dedicated QUIC Connections (DoQ) | Implemented |
| 9460 | Service Binding (SVCB) and HTTPS Resource Records | Implemented (with typed accessors for ALPN, port, IPv4/IPv6 hints) |

Out of scope for the current toolkit: RFC 7873 DNS cookies, RFC 7816 QNAME minimisation, RFC 8198 aggressive NSEC caching, RFC 9156 (revised QNAME minimisation), DNS-SD (RFC 6763), mDNS (RFC 6762).

## Go conventions (in addition to ~/.claude/docs/go.md)

- Wire encoding: hand-written, no reflection. Each RR type has `pack(*packer) error` / `unpack(*unpacker) error`.
- Length-prefixed reads: every reader checks bounds before advancing offset.
- Compression pointer loops: detect via offset-set or hop counter; reject malformed input with typed error.
- Test data: capture real `dig +qr` packets as hex fixtures under `testdata/`.

## Dispatching on rdata type — DO NOT type-switch on the interface

`rdata.A` and `rdata.AAAA` have identical method sets (`Type()`, `Pack()`, `Addr()`); `rdata.SVCB` is a structural superset of `rdata.CNAME` (both expose `Target()`). Go interface satisfaction is structural, so:

- A `*svcb` value satisfies `rdata.CNAME` and will match a `case rdata.CNAME:` arm BEFORE a `case rdata.SVCB:` arm in a type switch.
- An `aaaaData` value satisfies `rdata.A` and vice versa; whichever arm appears first wins.

**Rule:** dispatch on `rec.Type()` (or `rd.Type()`) and then assert to the concrete interface — NEVER `switch rd := rec.RData().(type)`.

```go
// good
switch rec.Type() {
case rrtype.A:
    addr := rec.RData().(rdata.A).Addr()
case rrtype.AAAA:
    addr := rec.RData().(rdata.AAAA).Addr()
case rrtype.SVCB, rrtype.HTTPS:
    s := rec.RData().(rdata.SVCB)
    ...
}

// bad — picks the wrong case for AAAA / SVCB
switch rd := rec.RData().(type) {
case rdata.A: ...
case rdata.CNAME: ...   // also matches SVCB
}
```

This rule applies to all rdata interface dispatch. If a future call-site needs the same logic, add the dispatch helper to the package that owns it rather than duplicating the type switch.

## Pre-flight for any task in this repo

- Read `~/.claude/docs/go.md` before writing Go.
- Read `~/.claude/docs/git-operations.md` before any git op.
- Editing tracked files → use a worktree under `.worktrees/<branch>`.
