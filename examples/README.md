# Examples

Runnable examples for [github.com/lestrrat-go/acidns](https://github.com/lestrrat-go/acidns).
Each file contains exactly one `Example_<area>_<op>` function with a verified `// OUTPUT:` block; run them all with:

```
go test ./examples/...
```

## dnsmsg / wire format

- [dnsmsg_build](dnsmsg_build_example_test.go) — build a query with the `Builder`.
- [dnsmsg_marshal](dnsmsg_marshal_example_test.go) — Marshal / Unmarshal round-trip.
- [edns_options](edns_options_example_test.go) — typed EDNS option helpers (cookies, ECS, EDE, ...).
- [rrset_group](rrset_group_example_test.go) — partition records into RRsets per RFC 2181.
- [svcb_build](svcb_build_example_test.go) — build SVCB / HTTPS records with typed SvcParams.

## dnsname

- [dnsname_parse](dnsname_parse_example_test.go) — parse and walk DNS names.

## dnszone

- [dnszone_parse](dnszone_parse_example_test.go) — parse RFC 1035 master files.

## Client

- [dnsclient_resolve](dnsclient_resolve_example_test.go) — basic `Resolver.Resolve`.
- [dnsclient_resolve_as](dnsclient_resolve_as_example_test.go) — generic typed lookup with `ResolveAs[T]`.
- [dnsupdate_build](dnsupdate_build_example_test.go) — build an RFC 2136 UPDATE.
- [axfr_transfer](axfr_transfer_example_test.go) — pull a zone with AXFR.
- [ixfr_transfer](ixfr_transfer_example_test.go) — drive an RFC 1995 incremental transfer.
- [notify_send](notify_send_example_test.go) — send RFC 1996 NOTIFY.
- [resolvconf_parse](resolvconf_parse_example_test.go) — parse `/etc/resolv.conf`.
- [specialuse_disposition](specialuse_disposition_example_test.go) — RFC 6761 special-use name handling.
- [ddr_discover](ddr_discover_example_test.go) — Designated Resolver discovery (RFC 9462).
- [amt_discover](amt_discover_example_test.go) — RFC 8777 AMT relay discovery.
- [recursive_resolve](recursive_resolve_example_test.go) — iterative resolver against a scripted dialer.

## Transports

- [dot_exchange](dot_exchange_example_test.go) — DNS over TLS (RFC 7858).
- [doh_exchange](doh_exchange_example_test.go) — DNS over HTTPS (RFC 8484).
- [doq_exchange](doq_exchange_example_test.go) — DNS over QUIC (RFC 9250).
- [dnscrypt_decode_cert](dnscrypt_decode_cert_example_test.go) — parse and verify a DNSCrypt v2 certificate.

## Server

- [dnsserver_authoritative](dnsserver_authoritative_example_test.go) — run an authoritative server.
- [dnsserver_chaos](dnsserver_chaos_example_test.go) — id.server / version.bind handler.
- [chaos_handler](chaos_handler_example_test.go) — invoke the CHAOS handler directly.
- [dnsserver_acl](dnsserver_acl_example_test.go) — wrap a Handler with source-IP ACLs.
- [forward_cache](forward_cache_example_test.go) — caching forwarder over a stub upstream.

## Security

- [tsig_sign_verify](tsig_sign_verify_example_test.go) — TSIG sign + verify (RFC 8945).
- [sig0_sign_verify](sig0_sign_verify_example_test.go) — SIG(0) sign + verify (RFC 2931).
- [dnssec_verify](dnssec_verify_example_test.go) — verify an RRSIG against a DNSKEY.
- [validator_nta](validator_nta_example_test.go) — Negative Trust Anchor store.
- [cookies_roundtrip](cookies_roundtrip_example_test.go) — RFC 7873 / 9018 DNS Cookies.

## Zones

- [classless_delegation](classless_delegation_example_test.go) — RFC 2317 reverse-DNS CNAMEs.

## Other

- [dso_tlv](dso_tlv_example_test.go) — DSO (RFC 8490) TLV codec.
- [mdns_parse](mdns_parse_example_test.go) — parse a captured mDNS browse response.

## Adding an example

1. Pick a name `<area>_<op>` (e.g. `dnsclient_lookuphost`). Use lowercase with underscores.
2. Create `<area>_<op>_example_test.go` with `package examples_test`.
3. Define exactly one function `Example_<area>_<op>()`.
4. Print deterministic output and end the function with a `// OUTPUT:` block — `go test` will fail if the printed output diverges.
5. Add an entry to this README under the right section.
