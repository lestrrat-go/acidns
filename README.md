# acidns

A full-fledged DNS toolkit for Go.

```
go get github.com/lestrrat-go/acidns
```

## What it gives you

- **Wire codec** for RFC 1034/1035 plus the modern extensions (EDNS0, DNSSEC,
  SVCB/HTTPS, EDNS Cookies, Extended Errors, Padding, …) — hand-written, no
  reflection.
- **Resolvers**: a stub resolver, an iterative recursive resolver with
  RFC 2308 negative caching and lame-server detection, and the convenience
  `LookupHost` / `ResolveAs[T]` helpers.
- **Transports**: UDP, TCP (with RFC 7766 keep-alive + RFC 7828 idle hints),
  DoT (RFC 7858), DoH (RFC 8484), DoQ (RFC 9250), DNSCrypt v2.
- **Server framework**: pluggable `Handler` / `ResponseWriter`, ACL and
  rate-limit middleware, authoritative master-file backend, caching forwarder,
  recursive resolver.
- **Spec helpers**: AXFR, IXFR, NOTIFY, dynamic update (RFC 2136), TSIG,
  SIG(0), DDR (RFC 9462), AMT relay discovery (RFC 8777), mDNS browse + publish
  (RFC 6762/6763).

The supported-RFCs matrix lives in [CLAUDE.md](./CLAUDE.md#supported-rfcs).

## Quick start

```go
package main

import (
    "context"
    "fmt"

    "github.com/lestrrat-go/acidns"
)

func main() {
    r, err := acidns.SystemResolver()
    if err != nil {
        panic(err)
    }
    addrs, err := acidns.LookupHost(context.Background(), r, "example.com.")
    if err != nil {
        panic(err)
    }
    for _, a := range addrs {
        fmt.Println(a)
    }
}
```

`SystemResolver` reads `/etc/resolv.conf`. To pin specific upstreams instead:

```go
r, err := acidns.NewResolver(
    acidns.WithServers(netip.MustParseAddrPort("1.1.1.1:53")),
)
```

To use an encrypted transport:

```go
ex, err := dot.NewExchanger("1.1.1.1:853", dot.WithServerName("one.one.one.one"))
if err != nil { panic(err) }
r, err := acidns.NewResolver(acidns.WithExchanger(ex))
```

## Typed accessors

Records are concrete structs with strongly typed accessors — no `interface{}`:

```go
addrs, err := acidns.ResolveAs[rdata.A](ctx, r, wire.MustParseName("example.com"))
for _, a := range addrs {
    fmt.Println(a.Addr())
}
```

Many-case dispatch uses a Go type switch:

```go
switch v := rec.RData().(type) {
case rdata.A:    fmt.Println("A", v.Addr())
case rdata.AAAA: fmt.Println("AAAA", v.Addr())
case rdata.MX:   fmt.Println("MX", v.Priority(), v.Target())
}
```

## Servers

```go
h := acidns.HandlerFunc(func(ctx context.Context, w acidns.ResponseWriter, q wire.Message) {
    resp, _ := wire.NewMessageBuilder().ID(q.ID()).Response(true).Build()
    _ = w.WriteMsg(resp)
})
srv, err := acidns.NewUDPServer(netip.MustParseAddrPort("127.0.0.1:5353"), h)
if err != nil { panic(err) }
_ = srv.Run(ctx)
```

The `forward/` package is a caching forwarder; `authoritative/` serves a
master-file zone; `recursive/` is an iterative resolver. They all satisfy
the same `Handler` interface and compose with the ACL and rate-limit
middleware in the root package.

## Documentation

- Per-package godoc: `go doc github.com/lestrrat-go/acidns/<pkg>`.
- Runnable examples: see [`examples/`](./examples/).
- RFC support matrix and design philosophy: [CLAUDE.md](./CLAUDE.md).

## License

MIT.
