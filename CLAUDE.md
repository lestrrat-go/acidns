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

Status legend: **Implemented** = working code with tests; **Partial** = documented subset; **Followed** = behavioural conformance, no specific code; **Out of scope** = explicitly not addressed in this version.

### Basic operations

| RFC | Title | Status |
|-----|-------|--------|
| 1034 | Domain Names — Concepts and Facilities | Implemented (authoritative §4.3.2 lookup algorithm) |
| 1035 | Domain Names — Implementation and Specification | Implemented (wire format, name compression §4.1.4, master files §5, TCP framing §4.2.2) |
| 1982 | Serial Number Arithmetic | Implemented (used by IXFR comparison) |
| 2308 | Negative Caching of DNS Queries | Implemented (recursive cache caps at SOA MINIMUM per §5) |
| 2782 | Service Location (SRV) | Implemented (typed `rdata.SRV`) |
| 3596 | DNS Extensions to Support IPv6 | Implemented (AAAA records) |
| 3597 | Handling of Unknown DNS RR Types | Implemented (TYPEnnn parsing, generic `\#` writer form) |
| 4592 | Role of the Wildcard Label in the DNS | Implemented (authoritative wildcard synthesis with closest-encloser semantics) |
| 6761 | Special-Use Domain Names | Implemented (`dnsclient/specialuse`: localhost / invalid / test / onion / alt; `local` deferred to mDNS) |
| 6762 | Multicast DNS (mDNS) | Implemented (browse + parse via `mdns/`; service publication is out of scope) |
| 6763 | DNS-Based Service Discovery (DNS-SD) | Implemented (`mdns.Browse` returns Service entries with SRV/TXT/A/AAAA merged) |
| 6891 | Extension Mechanisms for DNS (EDNS(0)) | Implemented (OPT pseudo-RR, UDP size, DO bit, extended RCODE) |
| 7766 | DNS Transport over TCP | Partial (server-side multi-query per connection + idle timeout; no client-side keepalive) |
| 8499 | DNS Terminology | Followed (no master/slave terminology in code or docs — primary/secondary throughout) |
| ANAME draft (`draft-ietf-dnsop-aname`) | Address-specific aliases | Out of scope (still a draft; no IANA RR type assignment) |

### Update operations

| RFC | Title | Status |
|-----|-------|--------|
| 1995 | Incremental Zone Transfer (IXFR) | Implemented client; server falls back to AXFR per §3 |
| 2136 | Dynamic Updates in the Domain Name System | Implemented (UPDATE opcode, prerequisites, add/delete RRset, delete record) |
| 5936 | DNS Zone Transfer Protocol (AXFR) | Implemented (single-message AXFR, server + client) |
| 7477 | Child-to-Parent Synchronization (CSYNC) | Implemented (typed `rdata.CSYNC`) |

### Secure DNS operations

| RFC | Title | Status |
|-----|-------|--------|
| 2931 | DNS Request and Transaction Signatures (SIG(0)) | Implemented (sign + verify in `sig0/` for RSASHA256, RSASHA512, ECDSAP256, ECDSAP384, Ed25519) |
| 3007 | Secure Domain Name System Dynamic Update | Implemented (`dnsupdate.Builder.SignedWire` produces TSIG-signed UPDATE wire bytes) |
| 3110 | RSA SIG/KEY Resource Records | Implemented (RSA pubkey wire format) |
| 4034 | Resource Records for the DNS Security Extensions | Implemented (DNSKEY, RRSIG, NSEC; canonical form §6) |
| 4035 | Protocol Modifications for DNSSEC | Partial (verification primitives only — no chain-of-trust walker, no NSEC/NSEC3 negative-proof validation) |
| 4509 | Use of SHA-256 in DNSSEC Delegation Signer | Implemented (DS digest type 2) |
| 5155 | DNSSEC Hashed Authenticated Denial of Existence | Partial (NSEC3 + NSEC3PARAM encode/decode; validator does not yet consume) |
| 5702 | RSA/SHA-2 in DNSSEC | Implemented (RSASHA256, RSASHA512) |
| 6605 | Elliptic Curve DSA for DNSSEC | Implemented (ECDSAP256SHA256, ECDSAP384SHA384) |
| 6698 | DNS-Based Authentication of Named Entities (DANE) — TLSA | Implemented (typed `rdata.TLSA` with usage / selector / matching enums) |
| 6840 | Clarifications and Implementation Notes for DNSSEC | Followed (canonical-form rules per §6 implemented; algorithm requirements per §5 followed) |
| 6844 | DNS Certification Authority Authorization (legacy) | Implemented (succeeded by RFC 8659; same wire format) |
| 6944 | DNSKEY Algorithm Implementation Status | Followed (modern algorithms — RSASHA256, ECDSAP256, ECDSAP384, Ed25519 — implemented; legacy algorithms and SHA-1 only where required by other RFCs) |
| 6975 | Signaling Cryptographic Algorithm Understanding | Implemented (`NewAlgorithmUnderstood` for DAU/DHU/N3U EDNS options) |
| 7858 | DNS over Transport Layer Security (DoT) | Implemented |
| 8080 | Edwards-Curve DSA for DNSSEC | Implemented (Ed25519; Ed448 not yet — IANA-listed but rare) |
| 8162 | Using Secure DNS to Associate Certificates with Domain Names for S/MIME | Implemented (typed `rdata.SMIMEA`) |
| 8484 | DNS Queries over HTTPS (DoH) | Implemented (POST + GET) |
| 8624 | DNSSEC Algorithm Implementation Requirements | Followed |
| 8659 | DNS Certification Authority Authorization (CAA) | Implemented |
| 8945 | Secret Key Transaction Authentication for DNS (TSIG) | Implemented (hmac-sha1/256/384/512; bridge into UPDATE via `dnsupdate.SignedWire`) |
| 9250 | DNS over Dedicated QUIC Connections (DoQ) | Implemented |
| 9460 | Service Binding (SVCB) and HTTPS Resource Records | Implemented (typed accessors for ALPN, port, IPv4/IPv6 hints) |

### Out of scope

| RFC | Title | Reason |
|-----|-------|--------|
| 6762 publishing | Service announcement (mDNS) | Browse-only for now; announcer requires interface enumeration + cache-flush handling not yet built |
| 7816 / 9156 | QNAME Minimisation | Recursive resolver is straight-walk for now |
| 7873 | DNS Cookies | EDNS option code reserved (`EDNSOptionCookie`) but no cookie state machine |
| 8198 | Aggressive NSEC Caching | Builds on full NSEC validation, not yet present |
| 8914 | Extended DNS Errors | Option code reserved (`EDNSOptionExtendedDNS`) but server doesn't yet emit |

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
