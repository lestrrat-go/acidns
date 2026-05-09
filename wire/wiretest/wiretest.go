// Package wiretest provides one-line fixture builders for tests that need
// to synthesise DNS messages and records. It is intended for use from
// _test.go files anywhere in or outside the acidns module — production
// code should construct messages explicitly via wire.NewBuilder.
//
// Functions here panic on programmer error (invalid IP literal, oversized
// builder) instead of returning an error. They mirror the wire.MustParseName
// convention.
package wiretest

import (
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// Query builds a minimal client query (RD=1) for the given name and type.
func Query(name wire.Name, t rrtype.Type) wire.Message {
	m, err := wire.NewBuilder().
		ID(0).
		RecursionDesired(true).
		Question(wire.NewQuestion(name, t)).
		Build()
	if err != nil {
		panic(err)
	}
	return m
}

// Response builds a NoError response that echoes q's question and carries
// the supplied answer records. Authoritative is false (use Authoritative
// if you need AA=1).
func Response(q wire.Message, answers ...wire.Record) wire.Message {
	b := wire.NewBuilder().
		ID(q.ID()).
		Response(true).
		RecursionDesired(q.Flags().RecursionDesired()).
		RecursionAvailable(true)
	if qs := q.Questions(); len(qs) > 0 {
		b = b.Question(qs[0])
	}
	for _, a := range answers {
		b = b.Answer(a)
	}
	m, err := b.Build()
	if err != nil {
		panic(err)
	}
	return m
}

// Authoritative is like Response but with AA=1.
func Authoritative(q wire.Message, answers ...wire.Record) wire.Message {
	b := wire.NewBuilder().
		ID(q.ID()).
		Response(true).
		Authoritative(true).
		RecursionDesired(q.Flags().RecursionDesired()).
		RecursionAvailable(true)
	if qs := q.Questions(); len(qs) > 0 {
		b = b.Question(qs[0])
	}
	for _, a := range answers {
		b = b.Answer(a)
	}
	m, err := b.Build()
	if err != nil {
		panic(err)
	}
	return m
}

// NXDOMAIN returns an authoritative NXDOMAIN response to q.
func NXDOMAIN(q wire.Message) wire.Message {
	return rcodeResponse(q, wire.RCODENXDomain, true)
}

// ServFail returns a SERVFAIL response to q. Authoritative=false because a
// resolver returning SERVFAIL is by definition the upstream's failure, not
// a zone-authoritative answer.
func ServFail(q wire.Message) wire.Message {
	return rcodeResponse(q, wire.RCODEServFail, false)
}

// Refused returns a REFUSED response to q.
func Refused(q wire.Message) wire.Message {
	return rcodeResponse(q, wire.RCODERefused, false)
}

// EmptyResponse returns a NoError response with no question and no records.
// Useful as a placeholder in test fakes that need any wire.Message but do
// not exercise its contents.
func EmptyResponse() wire.Message {
	m, err := wire.NewBuilder().Response(true).Build()
	if err != nil {
		panic(err)
	}
	return m
}

func rcodeResponse(q wire.Message, code wire.RCODE, aa bool) wire.Message {
	b := wire.NewBuilder().
		ID(q.ID()).
		Response(true).
		Authoritative(aa).
		RecursionDesired(q.Flags().RecursionDesired()).
		RecursionAvailable(true).
		RCODE(code)
	if qs := q.Questions(); len(qs) > 0 {
		b = b.Question(qs[0])
	}
	m, err := b.Build()
	if err != nil {
		panic(err)
	}
	return m
}

// ARecord builds an A-record for ip parsed from a v4 dotted-quad string.
// Panics if ip does not parse as an IPv4 address.
func ARecord(name wire.Name, ttl time.Duration, ip string) wire.Record {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		panic(err)
	}
	if !addr.Is4() {
		panic("wiretest.ARecord: not an IPv4 address: " + ip)
	}
	return wire.NewRecord(name, ttl, rdata.MustNewA(addr))
}

// AAAARecord builds an AAAA-record for ip parsed as IPv6.
// Panics if ip does not parse as an IPv6 address.
func AAAARecord(name wire.Name, ttl time.Duration, ip string) wire.Record {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		panic(err)
	}
	if !addr.Is6() || addr.Is4In6() {
		panic("wiretest.AAAARecord: not an IPv6 address: " + ip)
	}
	return wire.NewRecord(name, ttl, rdata.MustNewAAAA(addr))
}

// CNAMERecord builds a CNAME record pointing to target.
// Panics if target is not a valid name (wiretest is for fixtures only).
func CNAMERecord(name wire.Name, ttl time.Duration, target wire.Name) wire.Record {
	return wire.NewRecord(name, ttl, rdata.MustNewCNAME(target))
}

// NSRecord builds an NS record naming server.
// Panics if server is not a valid name (wiretest is for fixtures only).
func NSRecord(name wire.Name, ttl time.Duration, server wire.Name) wire.Record {
	return wire.NewRecord(name, ttl, rdata.MustNewNS(server))
}

// PTRRecord builds a PTR record pointing to target.
// Panics if target is not a valid name (wiretest is for fixtures only).
func PTRRecord(name wire.Name, ttl time.Duration, target wire.Name) wire.Record {
	return wire.NewRecord(name, ttl, rdata.MustNewPTR(target))
}

// MXRecord builds an MX record with the given preference and exchange.
// Panics if exchange is the zero name (wiretest is for fixtures only).
func MXRecord(name wire.Name, ttl time.Duration, pref uint16, exchange wire.Name) wire.Record {
	return wire.NewRecord(name, ttl, rdata.MustNewMX(pref, exchange))
}

// TXTRecord builds a TXT record. Panics if any string exceeds the per-string
// 255-octet limit (which is rdata.NewTXT's only error mode).
func TXTRecord(name wire.Name, ttl time.Duration, strs ...string) wire.Record {
	rd, err := rdata.NewTXT(strs...)
	if err != nil {
		panic(err)
	}
	return wire.NewRecord(name, ttl, rd)
}

// SOARecord builds a SOA record for an apex. Panics if either mname or
// rname is the zero name (wiretest is for fixtures only).
func SOARecord(name wire.Name, ttl time.Duration, mname, rname wire.Name, serial uint32, refresh, retry, expire, minimum time.Duration) wire.Record {
	return wire.NewRecord(name, ttl, rdata.MustNewSOA(mname, rname, serial, refresh, retry, expire, minimum))
}
