// Package wiretest provides fixture builders for tests that need to
// synthesise DNS messages and records. Internal to the acidns module
// (under internal/); not part of the library's public API.
//
// Every function returns an error rather than panicking. Tests are
// expected to wrap each call in require.NoError. The fixture builders
// hand back errors verbatim from the underlying wire / rdata
// constructors so a misconfigured fixture surfaces as a test
// failure on the offending line.
package wiretest

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// Query builds a minimal client query (RD=1) for the given name and type.
func Query(name wire.Name, t rrtype.Type) (wire.Message, error) {
	return wire.NewMessageBuilder().
		ID(0).
		RecursionDesired(true).
		Question(wire.NewQuestion(name, t)).
		Build()
}

// Response builds a NoError response that echoes q's question and carries
// the supplied answer records. Authoritative is false (use Authoritative
// if you need AA=1).
func Response(q wire.Message, answers ...wire.Record) (wire.Message, error) {
	b := wire.NewMessageBuilder().
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
	return b.Build()
}

// Authoritative is like Response but with AA=1.
func Authoritative(q wire.Message, answers ...wire.Record) (wire.Message, error) {
	b := wire.NewMessageBuilder().
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
	return b.Build()
}

// NXDOMAIN returns an authoritative NXDOMAIN response to q.
func NXDOMAIN(q wire.Message) (wire.Message, error) {
	return rcodeResponse(q, wire.RCODENXDomain, true)
}

// ServFail returns a SERVFAIL response to q. Authoritative=false because a
// resolver returning SERVFAIL is by definition the upstream's failure, not
// a zone-authoritative answer.
func ServFail(q wire.Message) (wire.Message, error) {
	return rcodeResponse(q, wire.RCODEServFail, false)
}

// Refused returns a REFUSED response to q.
func Refused(q wire.Message) (wire.Message, error) {
	return rcodeResponse(q, wire.RCODERefused, false)
}

// EmptyResponse returns a NoError response with no question and no records.
// Useful as a placeholder in test fakes that need any wire.Message but do
// not exercise its contents.
func EmptyResponse() (wire.Message, error) {
	return wire.NewMessageBuilder().Response(true).Build()
}

func rcodeResponse(q wire.Message, code wire.RCODE, aa bool) (wire.Message, error) {
	b := wire.NewMessageBuilder().
		ID(q.ID()).
		Response(true).
		Authoritative(aa).
		RecursionDesired(q.Flags().RecursionDesired()).
		RecursionAvailable(true).
		RCODE(code)
	if qs := q.Questions(); len(qs) > 0 {
		b = b.Question(qs[0])
	}
	return b.Build()
}

// ARecord builds an A-record for ip parsed from a v4 dotted-quad string.
// Returns an error when ip does not parse as an IPv4 address.
func ARecord(name wire.Name, ttl time.Duration, ip string) (wire.Record, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return wire.Record{}, err
	}
	if !addr.Is4() {
		return wire.Record{}, fmt.Errorf("wiretest.ARecord: not an IPv4 address: %s", ip)
	}
	rd, err := rdata.NewA(addr)
	if err != nil {
		return wire.Record{}, err
	}
	return wire.NewRecord(name, ttl, rd), nil
}

// AAAARecord builds an AAAA-record for ip parsed as IPv6.
// Returns an error when ip does not parse as an IPv6 address.
func AAAARecord(name wire.Name, ttl time.Duration, ip string) (wire.Record, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return wire.Record{}, err
	}
	if !addr.Is6() || addr.Is4In6() {
		return wire.Record{}, fmt.Errorf("wiretest.AAAARecord: not an IPv6 address: %s", ip)
	}
	rd, err := rdata.NewAAAA(addr)
	if err != nil {
		return wire.Record{}, err
	}
	return wire.NewRecord(name, ttl, rd), nil
}

// CNAMERecord builds a CNAME record pointing to target.
func CNAMERecord(name wire.Name, ttl time.Duration, target wire.Name) (wire.Record, error) {
	rd, err := rdata.NewCNAME(target)
	if err != nil {
		return wire.Record{}, err
	}
	return wire.NewRecord(name, ttl, rd), nil
}

// NSRecord builds an NS record naming server.
func NSRecord(name wire.Name, ttl time.Duration, server wire.Name) (wire.Record, error) {
	rd, err := rdata.NewNS(server)
	if err != nil {
		return wire.Record{}, err
	}
	return wire.NewRecord(name, ttl, rd), nil
}

// PTRRecord builds a PTR record pointing to target.
func PTRRecord(name wire.Name, ttl time.Duration, target wire.Name) (wire.Record, error) {
	rd, err := rdata.NewPTR(target)
	if err != nil {
		return wire.Record{}, err
	}
	return wire.NewRecord(name, ttl, rd), nil
}

// MXRecord builds an MX record with the given preference and exchange.
func MXRecord(name wire.Name, ttl time.Duration, pref uint16, exchange wire.Name) (wire.Record, error) {
	rd, err := rdata.NewMX(pref, exchange)
	if err != nil {
		return wire.Record{}, err
	}
	return wire.NewRecord(name, ttl, rd), nil
}

// TXTRecord builds a TXT record. Returns an error when any string
// exceeds the per-string 255-octet limit (which is rdata.NewTXT's
// only error mode).
func TXTRecord(name wire.Name, ttl time.Duration, strs ...string) (wire.Record, error) {
	rd, err := rdata.NewTXT(strs...)
	if err != nil {
		return wire.Record{}, err
	}
	return wire.NewRecord(name, ttl, rd), nil
}

// SOARecord builds a SOA record for an apex.
func SOARecord(name wire.Name, ttl time.Duration, mname, rname wire.Name, serial uint32, refresh, retry, expire, minimum time.Duration) (wire.Record, error) {
	rd, err := rdata.NewSOA(mname, rname, serial, refresh, retry, expire, minimum)
	if err != nil {
		return wire.Record{}, err
	}
	return wire.NewRecord(name, ttl, rd), nil
}
