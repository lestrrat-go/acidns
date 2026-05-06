// Package rrtype defines DNS resource record type and class identifiers.
package rrtype

import (
	"fmt"
	"strconv"
	"strings"
)

// Type is a DNS resource record type as it appears on the wire.
type Type uint16

// Standard RR types. The list is the common subset used in the toolkit;
// values not listed here render as "TYPEnnn" per RFC 3597.
const (
	A          Type = 1
	NS         Type = 2
	CNAME      Type = 5
	SOA        Type = 6
	PTR        Type = 12
	HINFO      Type = 13
	MX         Type = 15
	TXT        Type = 16
	RP         Type = 17
	AFSDB      Type = 18  // RFC 1183
	X25        Type = 19  // RFC 1183
	ISDN       Type = 20  // RFC 1183
	RT         Type = 21  // RFC 1183
	NSAP       Type = 22  // RFC 1706 (formerly RFC 1348)
	NSAPPTR    Type = 23  // RFC 1706
	LOC        Type = 29  // RFC 1876
	AAAA       Type = 28
	SRV        Type = 33
	NAPTR      Type = 35
	APL        Type = 42  // RFC 3123
	OPT        Type = 41
	DS         Type = 43
	SSHFP      Type = 44
	IPSECKEY   Type = 45  // RFC 4025
	RRSIG      Type = 46
	NSEC       Type = 47
	DNSKEY     Type = 48
	DHCID      Type = 49  // RFC 4701
	NSEC3      Type = 50
	NSEC3PARAM Type = 51
	TLSA       Type = 52
	SMIMEA     Type = 53
	HIP        Type = 55  // RFC 5205
	CDS        Type = 59
	CDNSKEY    Type = 60
	CSYNC      Type = 62
	ZONEMD     Type = 63  // RFC 8976
	SVCB       Type = 64
	HTTPS      Type = 65
	SPF        Type = 99
	NID        Type = 104 // RFC 6742
	L32        Type = 105 // RFC 6742
	L64        Type = 106 // RFC 6742
	LP         Type = 107 // RFC 6742
	EUI48      Type = 108 // RFC 7043
	EUI64      Type = 109 // RFC 7043
	URI        Type = 256 // RFC 7553
	CAA        Type = 257
	RESINFO    Type = 261 // RFC 9606
	NXNAME     Type = 128 // draft-ietf-dnsop-compact-denial-of-existence

	ANY        Type = 255
	AXFR       Type = 252
	IXFR       Type = 251
)

var typeNames = map[Type]string{
	A: "A", NS: "NS", CNAME: "CNAME", SOA: "SOA", PTR: "PTR", HINFO: "HINFO",
	MX: "MX", TXT: "TXT", RP: "RP", AFSDB: "AFSDB", X25: "X25", ISDN: "ISDN",
	RT: "RT", NSAP: "NSAP", NSAPPTR: "NSAP-PTR", LOC: "LOC",
	AAAA: "AAAA", SRV: "SRV", NAPTR: "NAPTR", OPT: "OPT",
	APL: "APL", DS: "DS", SSHFP: "SSHFP", IPSECKEY: "IPSECKEY",
	RRSIG: "RRSIG", NSEC: "NSEC", DNSKEY: "DNSKEY", DHCID: "DHCID",
	NSEC3: "NSEC3", NSEC3PARAM: "NSEC3PARAM", TLSA: "TLSA", SMIMEA: "SMIMEA",
	HIP: "HIP", CDS: "CDS", CDNSKEY: "CDNSKEY", CSYNC: "CSYNC", ZONEMD: "ZONEMD",
	SVCB: "SVCB", HTTPS: "HTTPS", SPF: "SPF",
	NID: "NID", L32: "L32", L64: "L64", LP: "LP",
	EUI48: "EUI48", EUI64: "EUI64",
	URI: "URI", CAA: "CAA", RESINFO: "RESINFO", NXNAME: "NXNAME",
	ANY: "ANY", AXFR: "AXFR", IXFR: "IXFR",
}

var typeByName = func() map[string]Type {
	m := make(map[string]Type, len(typeNames))
	for k, v := range typeNames {
		m[v] = k
	}
	return m
}()

// String returns the canonical mnemonic, or "TYPEnnn" for unknown values.
func (t Type) String() string {
	if s, ok := typeNames[t]; ok {
		return s
	}
	return "TYPE" + strconv.FormatUint(uint64(t), 10)
}

// Parse parses a type mnemonic ("A", "AAAA", ...) or the RFC 3597 generic
// form "TYPEnnn". It returns false if s does not match either form.
func Parse(s string) (Type, bool) {
	if t, ok := typeByName[strings.ToUpper(s)]; ok {
		return t, true
	}
	if len(s) > 4 && strings.EqualFold(s[:4], "TYPE") {
		v, err := strconv.ParseUint(s[4:], 10, 16)
		if err != nil {
			return 0, false
		}
		return Type(v), true
	}
	return 0, false
}

// Class is a DNS resource record class.
type Class uint16

const (
	ClassIN   Class = 1
	ClassCH   Class = 3
	ClassHS   Class = 4
	ClassNONE Class = 254
	ClassANY  Class = 255
)

func (c Class) String() string {
	switch c {
	case ClassIN:
		return "IN"
	case ClassCH:
		return "CH"
	case ClassHS:
		return "HS"
	case ClassNONE:
		return "NONE"
	case ClassANY:
		return "ANY"
	default:
		return fmt.Sprintf("CLASS%d", uint16(c))
	}
}
