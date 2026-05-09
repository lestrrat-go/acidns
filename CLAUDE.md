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

- Public types = interfaces ONLY when they prevent footguns (mutability, invariants, sum-type discriminators). Plain value carriers (rdata payloads, parsed records, transparent results) are exported structs with unexported fields. Constructors validate.
- Constructors take functional options: `New(...Option)`. Options live in `option.go` per package.
- Builders for compound objects: `pkg.NewXxxBuilder().A(...).B(...).Build() (Xxx, error)`.
- Strongly typed accessors. NEVER expose `interface{}` / `any` in public signatures unless genuinely polymorphic.
- Sub-packages by concern, not by layer. One responsibility per package.
- Errors: sentinel `var ErrXxx = errors.New(...)` for matchable conditions; wrap with `fmt.Errorf("...: %w", err)`.
- No init() side effects. No package-level mutable state.

## Layout

```
acidns/                root: high-level convenience layer + UDP/TCP exchangers + Server framework
  resolver.go          Resolver, NewResolver, WithAttempts/WithDNSSEC/etc.
  lookup.go            LookupHost, LookupA, LookupMX, ...
  extract.go           Extract[T], ResolveAs[T]
  exchanger.go         Exchanger / StreamExchanger / MessageStream interfaces
  exchanger_udp.go     NewUDPExchanger, WithUDPTimeout, WithUDPReadBufferSize
  exchanger_tcp.go     NewTCPExchanger, WithTCPTimeout
  server.go            Server, Handler, HandlerFunc, ResponseWriter
  server_udp.go        ListenUDP, UDPListenerOption
  server_tcp.go        ListenTCP, TCPListenerOption
  middleware_acl.go    NewACL, WithACLAllow, WithACLDeny
  middleware_ratelimit.go  NewRateLimit, WithRateLimitQPS, ...

  wire/                RFC 1034/1035 core: Message, Question, Record, Builder, EDNS
    rrtype/            RR type + class constants
    rdata/             rdata codecs (one file per RR type)
    wirebb/            "building blocks" — pure-function packer/unpacker, Name primitive
    wiretest/          fixture builders for tests (Query, Response, NXDOMAIN, ARecord, ...)
    name.go            wire.Name (alias to wirebb.Name) + ParseName/MustParseName/etc.
  zonefile/            RFC 1035 §5 master-file parser + writer
    classless/         RFC 2317 classless in-addr.arpa helper

  dnssec/              DNSSEC verification primitives (KeyTag, Verify, VerifyDS)
    validator/         chain-of-trust validator scaffold + NTAStore (RFC 4035)
  dso/                 DNS Stateful Operations TLV codec (RFC 8490)
  tsig/                RFC 8945 transaction signature
  sig0/                RFC 2931 SIG(0) signing/verification
  dnscrypt/            DNSCrypt v2 transport
  mdns/                RFC 6762 multicast DNS browse + DNS-SD

  dot/                 RFC 7858 DNS over TLS
  doh/                 RFC 8484 DNS over HTTPS
  doq/                 RFC 9250 DNS over QUIC

  amt/                 RFC 8777 AMT relay discovery
  axfr/                RFC 5936 AXFR client
  ddr/                 RFC 9462 Discovery of Designated Resolvers
  ixfr/                RFC 1995 IXFR client
  notify/              RFC 1996 NOTIFY client
  update/              RFC 2136 dynamic update builder
  resolvconf/          /etc/resolv.conf parser
  specialuse/          RFC 6761 special-use domain shortcut

  authoritative/       master-file-backed authoritative server
  chaos/               RFC 4892 id.server / hostname.bind handler
  forward/             caching DNS forwarder (UDP-with-TCP-fallback or DoT upstream)
  recursive/           iterative recursive resolver + cache

  internal/streamframe/  RFC 1035 §4.2.2 length-framed TCP/DoT/DoQ codec

  cmd/
    acidig/            dig-style CLI
    acidns-server/     authoritative / recursive / hybrid daemon
  examples/            runnable Example_<area>_<op> tests, one file per example
```

### Naming conventions

- Spec-named packages (`dnssec`, `tsig`, `sig0`, `dso`, `mdns`, `dnscrypt`, `dot`, `doh`, `doq`, `axfr`, `ixfr`, `notify`, `update`, `ddr`, `amt`, `chaos`, `specialuse`) match their RFC / protocol name.
- Functional names (`recursive`, `authoritative`, `resolvconf`, `zonefile`, `wire`) describe what the package does; used where no single spec name fits.
- Top-level convenience names (`Resolver`, `Server`, `Exchanger`) live in the root `acidns` package.
- The `wire/wirebb` and `dnssec/dnssecbb` (etc.) sub-packages follow jwx's xxxbb pattern: pure-function primitive layer below the ergonomic package.
- Option types are prefixed when they would otherwise collide in `acidns`: `UDPExchangerOption` vs `UDPListenerOption`, `WithUDPTimeout` vs `WithUDPReadBuffer`, etc.

## Supported RFCs

Status legend: **Implemented** = working code with tests; **Partial** = documented subset; **Followed** = behavioural conformance, no specific code; **Out of scope** = explicitly not addressed in this version.

### Basic operations

| RFC | Title | Status |
|-----|-------|--------|
| 1034 | Domain Names — Concepts and Facilities | Implemented (authoritative §4.3.2 lookup algorithm) |
| 1035 | Domain Names — Implementation and Specification | Implemented (wire format, name compression §4.1.4, master files §5, TCP framing §4.2.2; typed `rdata.HINFO` §3.3.2) |
| 1183 | Deprecated RR types | Implemented (typed `rdata.RP`/`AFSDB`/`X25`/`ISDN`/`RT`) |
| 2230 | Key Exchange Delegation Record (KX) | Implemented (typed `rdata.KX`) |
| 2930 | Secret Key Establishment for DNS (TKEY) | Implemented (typed `rdata.TKEY` with mode constants for server-assigned, DH, GSS-API, resolver-assigned, key-deletion) |
| 1348 / 1706 | NSAP / NSAP-PTR | Implemented (typed `rdata.NSAP`, `rdata.NSAPPTR`) |
| 1876 | LOC record | Implemented (typed `rdata.LOC`) |
| 1982 | Serial Number Arithmetic | Implemented (used by IXFR comparison) |
| 2181 | Clarifications to the DNS Specification | Implemented (`dnsmsg.RRset` + `GroupRecords` with min-TTL harmonisation per §5.2) |
| 2308 | Negative Caching of DNS Queries | Implemented (recursive cache caps at SOA MINIMUM per §5) |
| 2782 | Service Location (SRV) | Implemented (typed `rdata.SRV`) |
| 2915 / 3401–3403 | NAPTR | Implemented (typed `rdata.NAPTR`) |
| 2929 / 6895 | DNS IANA Considerations | Followed (procedural — type/class registries respected) |
| 3123 | APL record | Implemented (typed `rdata.APL` with negate flag + IPv4/IPv6 prefix items) |
| 3596 | DNS Extensions to Support IPv6 | Implemented (AAAA records) |
| 3597 | Handling of Unknown DNS RR Types | Implemented (TYPEnnn parsing, generic `\#` writer form) |
| 4025 | IPSECKEY | Implemented (typed `rdata.IPSECKEY` with all gateway types) |
| 4255 | SSHFP | Implemented (typed `rdata.SSHFP`) |
| 4398 | Storing Certificates in DNS (CERT) | Implemented (typed `rdata.CERT` with PKIX/SPKI/PGP/IPGP/etc. type constants) |
| 4343 | Case insensitivity | Followed (names canonicalised to lowercase wire form) |
| 4408 | SPF record | Implemented (typed `rdata.SPF` — wire format identical to TXT) |
| 4592 | Role of the Wildcard Label in the DNS | Implemented (authoritative wildcard synthesis with closest-encloser semantics) |
| 4701 | DHCID | Implemented (typed `rdata.DHCID`) |
| 4892 | id.server / hostname.bind | Implemented (`dnsserver/chaos` handler answers CHAOS-class TXT) |
| 5205 | HIP record | Implemented (typed `rdata.HIP`) |
| 6672 | DNAME Redirection in the DNS | Implemented (typed `rdata.DNAME` with uncompressed-target packing per §3.0) |
| 6742 | ILNP DNS resource records | Implemented (typed `rdata.NID`/`L32`/`L64`/`LP`) |
| 6761 | Special-Use Domain Names | Implemented (`dnsclient/specialuse`: localhost / invalid / test / onion / alt; `local` deferred to mDNS) |
| 6762 | Multicast DNS (mDNS) | Implemented (browse + parse + service publication via `mdns/`: probe → announce → goodbye lifecycle, cache-flush bit on owned records, conflict detection during probe per §8.1) |
| 6763 | DNS-Based Service Discovery (DNS-SD) | Implemented (`mdns.Browse` returns Service entries with SRV/TXT/A/AAAA merged) |
| 6891 | Extension Mechanisms for DNS (EDNS(0)) | Implemented (OPT pseudo-RR, UDP size, DO bit, extended RCODE) |
| 7043 | EUI48 / EUI64 | Implemented (typed `rdata.EUI48`, `rdata.EUI64`) |
| 7314 | EDNS EXPIRE option | Implemented (typed `dnsmsg.NewEDNSExpire` + parser) |
| 7344 | Automating DNSSEC Delegation Trust Maintenance | Implemented (typed `rdata.CDS`/`rdata.CDNSKEY`; RFC 8078 §4 delete-DS sentinel preserved) |
| 7553 | URI record | Implemented (typed `rdata.URI`) |
| 7766 | DNS Transport over TCP | Implemented (server-side multi-query per connection + idle timeout; client-side persistent connection via `NewTCPKeepAliveExchanger` honoring server-advertised idle) |
| 7828 | edns-tcp-keepalive | Implemented (typed `dnsmsg.NewTCPKeepalive` + parser; client auto-injects empty option, parses server timeout to schedule re-dial) |
| 7929 | DNS-Based Authentication of Named Entities for OpenPGP | Implemented (typed `rdata.OPENPGPKEY`) |
| 7871 | EDNS Client Subnet | Implemented (typed `dnsmsg.NewClientSubnet` + parser, IPv4/IPv6) |
| 7873 / 9018 | DNS Cookies | Implemented (typed wire codec + state machine in `cookies/`: client cache with BADCOOKIE retry; server SecretPool with timed rotation; RFC 9018 server-cookie HMAC over client cookie + addr + timestamp) |
| 8490 | DNS Stateful Operations | Partial (TLV codec + KeepAlive/RetryDelay/EncryptionPadding TLVs in `dso/`; no transport binding yet) |
| 8499 | DNS Terminology | Followed (no master/slave terminology in code or docs — primary/secondary throughout) |
| 8777 | DNS Reverse IP AMT Discovery | Implemented (`dnsclient/amt.Discover` — SRV `_amt._udp.<domain>` lookup, RFC 2782 ranking; typed `rdata.AMTRELAY` with all relay-type variants and discovery flag) |
| 8914 | Extended DNS Errors | Implemented (typed `dnsmsg.NewExtendedError` + parser, full info-code constants) |
| 8976 | ZONEMD | Implemented (typed `rdata.ZONEMD`) |
| 9461 | SVCB Mapping for DNS Servers | Implemented (`SvcParamDOHPath` + typed `SVCB.DOHPath()` accessor) |
| 9462 | Discovery of Designated Resolvers | Implemented (`dnsclient/ddr.Discover` returns ranked DoT/DoH/DoQ Endpoints) |
| 9567 | DNS Error Reporting | Implemented (Report-Channel EDNS option 18 + `BuildErrorReportName` synthetic-name helper) |
| 9606 | DNS Resolver Information (RESINFO) | Implemented (typed `rdata.RESINFO`) |
| 9660 | DNS Zone Version Option | Implemented (`dnsmsg.NewZoneVersionQuery`/`NewZoneVersionSOASerial`) |
| ANAME draft (`draft-ietf-dnsop-aname`) | Address-specific aliases | Out of scope (still a draft; no IANA RR type assignment) |

### Update operations

| RFC | Title | Status |
|-----|-------|--------|
| 1995 | Incremental Zone Transfer (IXFR) | Implemented client; server falls back to AXFR per §3 |
| 1996 | A Mechanism for Prompt Notification of Zone Changes | Implemented (`dnsclient/notify`; authoritative server ACKs and fires an optional `NotifyHandler`) |
| 2136 | Dynamic Updates in the Domain Name System | Implemented (UPDATE opcode, prerequisites, add/delete RRset, delete record) |
| 2317 | Classless IN-ADDR.ARPA Delegation | Implemented (helper `dnszone/classless.BuildDelegationCNAMEs`) |
| 5936 | DNS Zone Transfer Protocol (AXFR) | Implemented (multi-message streaming AXFR, server + client; server chunks at ~16 KB per message, client iterates messages until closing SOA) |
| 7477 | Child-to-Parent Synchronization (CSYNC) | Implemented (typed `rdata.CSYNC`) |
| 8764 | Apple's DNS Long-Lived Queries Protocol | Partial (`NewLLQ` builds the EDNS option for setup/refresh/event; full state machine not yet wired) |
| Update Lease (`draft-sekar-dns-ul`) | DNS Update Leases | Implemented (`NewUpdateLease` builds the UL EDNS option) |

### Secure DNS operations

| RFC | Title | Status |
|-----|-------|--------|
| 2537 / 3110 | RSAMD5 / RSA SIG/KEY Resource Records | Implemented (algorithm constants; RSAMD5 deprecated per RFC 8624 — recognised in registry, not used for new signatures) |
| 2931 | DNS Request and Transaction Signatures (SIG(0)) | Implemented (sign + verify in `sig0/` for RSASHA256, RSASHA512, ECDSAP256, ECDSAP384, Ed25519) |
| 3007 | Secure Domain Name System Dynamic Update | Implemented (`dnsupdate.Builder.SignedWire` produces TSIG-signed UPDATE wire bytes) |
| 3445 | Limiting the Scope of (DNS)KEY | Followed (DNSKEY flag constants `DNSKEYFlagZone`/`Revoke`/`SEP` reflect the post-3445 narrowed scope) |
| 4034 | Resource Records for the DNS Security Extensions | Implemented (DNSKEY, RRSIG, NSEC; canonical form §6) |
| 4035 | Protocol Modifications for DNSSEC | Implemented (verification primitives + framework `dnssec/validator` with NTA store, BogusPolicy, ValidateRRset/VerifyDelegation, chain Walker with iterative DS-probing, RFC 6840 §5.11 algorithm-rollover check, NSEC + NSEC3 denial of existence) |
| 4509 | Use of SHA-256 in DNSSEC Delegation Signer | Implemented (DS digest type 2) |
| 5155 | DNSSEC Hashed Authenticated Denial of Existence | Implemented (NSEC3 + NSEC3PARAM encode/decode; validator consumes via `dnssec/validator` chain Walker — closest-encloser proof, NXDOMAIN, NoData, opt-out delegations) |
| 5702 | RSA/SHA-2 in DNSSEC | Implemented (RSASHA256, RSASHA512) |
| 6605 | Elliptic Curve DSA for DNSSEC | Implemented (ECDSAP256SHA256, ECDSAP384SHA384) |
| 6698 | DNS-Based Authentication of Named Entities (DANE) — TLSA | Implemented (typed `rdata.TLSA` with usage / selector / matching enums) |
| 6840 | Clarifications and Implementation Notes for DNSSEC | Followed (canonical-form rules per §6 implemented; algorithm requirements per §5 followed) |
| 6844 | DNS Certification Authority Authorization (legacy) | Implemented (succeeded by RFC 8659; same wire format) |
| 6944 | DNSKEY Algorithm Implementation Status | Followed (modern algorithms — RSASHA256, ECDSAP256, ECDSAP384, Ed25519 — implemented; legacy algorithms and SHA-1 only where required by other RFCs) |
| 6975 | Signaling Cryptographic Algorithm Understanding | Implemented (`NewAlgorithmUnderstood` for DAU/DHU/N3U EDNS options) |
| 7858 | DNS over Transport Layer Security (DoT) | Implemented |
| 8080 | Edwards-Curve DSA for DNSSEC | Implemented (Ed25519; Ed448 algorithm constant present, signing/verification not wired) |
| 8162 | Using Secure DNS to Associate Certificates with Domain Names for S/MIME | Implemented (typed `rdata.SMIMEA`) |
| 8484 | DNS Queries over HTTPS (DoH) | Implemented (POST + GET) |
| 8624 | DNSSEC Algorithm Implementation Requirements | Followed |
| 8659 | DNS Certification Authority Authorization (CAA) | Implemented |
| 8945 | Secret Key Transaction Authentication for DNS (TSIG) | Implemented (hmac-sha1/256/384/512; bridge into UPDATE via `dnsupdate.SignedWire`) |
| 9250 | DNS over Dedicated QUIC Connections (DoQ) | Implemented |
| 9460 | Service Binding (SVCB) and HTTPS Resource Records | Implemented (typed accessors for ALPN, port, IPv4/IPv6 hints, dohpath) |
| Compact Denial draft (`draft-ietf-dnsop-compact-denial-of-existence`) | Compact Denial of Existence | Partial (NXNAME pseudo-type + `validator.IsCompactNXDOMAIN` classifier; chain Walker recognises NSEC/NSEC3 denial but Compact-Denial-specific bitmap interpretation pending) |
| DNSCrypt v2 (non-IETF) | Trusted DNS Queries | Implemented (`dnscrypt/`: cert parse + verify, X25519 + XChaCha20-Poly1305 encrypt/decrypt, transport.Exchanger) |

### Recursive resolver

| Aspect | Status |
|--------|--------|
| Iterative root → leaf walk with referrals | Implemented |
| Glue + out-of-bailiwick NS recursion | Implemented |
| CNAME chain following with loop detection / depth cap | Implemented |
| Lame-server detection (REFUSED/SERVFAIL skip + retry on remaining) | Implemented |
| Per-server smoothed RTT and failure-streak tracking | Implemented |
| EDNS UDPSize=1232 + TC=1 → TCP fall-back | Implemented |
| RFC 2308 §5 negative caching with SOA MINIMUM | Implemented |
| Optional DNSSEC validation via `recursive.WithValidator` (bogus → SERVFAIL+EDE6) | Implemented |
| Per-query timeout (`WithQueryTimeout`) | Implemented |
| QNAME minimisation (RFC 7816 / 9156) | Implemented (default on; `WithoutQNameMinimisation` opt-out; relaxed fallback on intermediate NXDOMAIN/SERVFAIL/non-conformant responses per §2.4) |
| Aggressive NSEC caching (RFC 8198) | Out of scope |
| Parallel A/AAAA address resolution | Out of scope |
| Per-upstream rate limiting / priming refresh | Out of scope |

### Out of scope

| RFC | Title | Reason |
|-----|-------|--------|
| 8198 | Aggressive NSEC Caching | Builds on full NSEC validation, not yet present |
| 4035 §3.1 / 5155 §7.2 | Authoritative DNSSEC signing + NSEC/NSEC3 closest-encloser proofs | The authoritative server serves the master-file's records verbatim; it does not sign zones, so it cannot produce the NSEC/NSEC3 chains required to prove non-existence. The validator-side counterpart (consuming and verifying NSEC closest-encloser proofs) IS implemented in `dnssec/validator/`. Adding signing would require: DNSKEY/RRSIG RR generation, NSEC/NSEC3 chain construction at zone-load, signed-zone serial bumping on UPDATE — out of scope for the current authoritative server. |

## Go conventions (in addition to ~/.claude/docs/go.md)

- Wire encoding: hand-written, no reflection. Each RR type has `pack(*packer) error` / `unpack(*unpacker) error`.
- Length-prefixed reads: every reader checks bounds before advancing offset.
- Compression pointer loops: detect via offset-set or hop counter; reject malformed input with typed error.
- Test data: capture real `dig +qr` packets as hex fixtures under `testdata/`.

## Dispatching on rdata type

Each typed rdata is a concrete struct (`rdata.A`, `rdata.AAAA`, `rdata.MX`, ..., `rdata.SVCB`, `rdata.HTTPS`) with unexported fields. `rdata.RData` is the umbrella interface implemented by all of them; `rdata.Typed` further requires a compile-time-constant `Type()` (every typed rdata satisfies Typed; `rdata.Unknown` deliberately does not). Type assertions on the concrete struct are precise: `rec.RData().(rdata.A)` matches only when the dynamic type is exactly `rdata.A`.

**Many-case dispatch — Go type switch:**

```go
switch v := rec.RData().(type) {
case rdata.A:
    addr := v.Addr()
case rdata.AAAA:
    addr := v.Addr()
case rdata.SVCB:
    ...
case rdata.HTTPS:
    ...
}
```

This is the cleanest form when handling several rdata types. forcetypeassert is happy because the type switch is checked by construction, and there are no naked `x.(T)` assertions.

**Single-record extraction — `wire.RDataAs[T]`:**

```go
if soa, ok := wire.RDataAs[rdata.SOA](rec); ok {
    serial := soa.Serial()
}
```

`RDataAs[T]` returns `(T, bool)`; the rrtype is inferred from `T`'s zero value. Prefer it over a manual `Type()` check followed by a naked assertion.

**Generic helpers across shape-equivalent rdata pairs** (e.g. SVCB and HTTPS) — type-set constraint:

```go
type svcbLike interface {
    rdata.SVCB | rdata.HTTPS
    Priority() uint16
    Target() wire.Name
    Params() []rdata.SVCBParam
}
func formatSVCB[T svcbLike](s T) string { ... }
```

**Slice extraction:** `acidns.Extract[T rdata.RData](records)` (allows Unknown via a special case) or `acidns.ResolveAs[T rdata.Typed](ctx, r, name)`.

**Note:** the older `switch rec.Type() { case rrtype.A: rec.RData().(rdata.A).Addr() }` form is no longer recommended — `forcetypeassert` flags the unchecked assertion, and the Go type switch reads just as clearly.

## Pre-flight for any task in this repo

- Read `~/.claude/docs/go.md` before writing Go.
- Read `~/.claude/docs/git-operations.md` before any git op.
- Editing tracked files → use a worktree under `.worktrees/<branch>`.
