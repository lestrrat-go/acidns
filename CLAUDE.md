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

## Layout (planned)

```
acidns/                root: top-level convenience re-exports only, no logic
  dnsmsg/              wire-format messages, headers, questions, RRs
    rrtype/            RR type constants + per-type record interfaces
    rdata/             rdata codecs (one file per RR type)
  dnsname/             domain name type + parsing/encoding (label compression lives here)
  dnsclient/           client-facing API (Resolver, Client, Exchange)
    transport/         udp, tcp, dot, doh, doq sub-packages
  dnsserver/           (later)
  dnszone/             (later)
  internal/            shared internals — never imported externally
```

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
