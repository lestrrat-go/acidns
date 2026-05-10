// Package rdata defines the typed resource record payloads carried inside a
// DNS message. Each typed payload is an exported struct with unexported
// fields and value-receiver accessors; construct via the per-type New
// constructors. Unknown carries the rdata for RR types this package does
// not decode.
package rdata

import (
	"errors"
	"fmt"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// ErrInvalidRData is returned when an rdata payload cannot be encoded or
// decoded against the rules of its type.
var ErrInvalidRData = errors.New("rdata: invalid")

// RData is the common interface implemented by every rdata payload. Type
// reports the RR type; Pack appends the rdata wire encoding to p, including
// the 16-bit length prefix is NOT this method's responsibility — it is
// written by dnsmsg, which back-fills the length after Pack returns.
//
// Per-type Pack methods are exported (they're part of this contract);
// per-type unpack helpers are deliberately unexported because
// decoding is dispatched through the package-level [Unpack], which
// is the public counterpart to [Pack]. The RFC 3597 unknown-type
// roundtrip uses [Pack]/[Unpack] at the package level — no per-type
// public Unpack is needed.
type RData interface {
	Type() rrtype.Type
	Pack(p *wirebb.Packer)
}

// Typed is the constraint for rdata payloads whose Type() is a compile-time
// constant. Every typed rdata in this package satisfies Typed; Unknown
// does not, because its RR type is carried in a per-instance field. Used
// as the constraint for ResolveAs so that ResolveAs[Unknown] is a compile
// error — Unknown has no inherent rrtype to query for.
type Typed interface {
	RData
	typedRData()
}

// Pack returns the wire-format bytes of r's payload (rdata only — no
// length prefix). Names in compressible positions are emitted with the
// internal codec's default policy; for canonicalisation purposes (e.g.
// DNSSEC), use a higher-level helper that walks each known type.
func Pack(r RData) []byte {
	p := wirebb.NewPacker(nil)
	r.Pack(p)
	return p.Bytes()
}

// Unpack reads rdlen bytes of rdata of type t from u and returns a typed
// RData value. Unknown types are returned as Unknown. An rdlen of 0 (used
// by RFC 2136 UPDATE messages to delete an RRset and by some prerequisite
// records) yields an Unknown of type t with no payload, regardless of t.
func Unpack(t rrtype.Type, u *wirebb.Unpacker, rdlen int) (RData, error) {
	if rdlen < 0 || u.Remaining() < rdlen {
		return nil, fmt.Errorf("%w: rdlen %d exceeds remaining %d", ErrInvalidRData, rdlen, u.Remaining())
	}
	if rdlen == 0 {
		return Unknown{typ: t, data: nil}, nil
	}
	end := u.Off() + rdlen

	r, err := unpackTyped(t, u, rdlen)
	if err != nil {
		return nil, err
	}
	if u.Off() != end {
		return nil, fmt.Errorf("%w: %s consumed %d of %d bytes", ErrInvalidRData, t, u.Off()-(end-rdlen), rdlen)
	}
	return r, nil
}

func unpackTyped(t rrtype.Type, u *wirebb.Unpacker, rdlen int) (RData, error) {
	switch t {
	case rrtype.A:
		return unpackA(u, rdlen)
	case rrtype.AAAA:
		return unpackAAAA(u, rdlen)
	case rrtype.CNAME:
		return unpackCNAME(u, rdlen)
	case rrtype.NS:
		return unpackNS(u, rdlen)
	case rrtype.PTR:
		return unpackPTR(u, rdlen)
	case rrtype.MX:
		return unpackMX(u, rdlen)
	case rrtype.TXT:
		return unpackTXT(u, rdlen)
	case rrtype.SOA:
		return unpackSOA(u, rdlen)
	case rrtype.SVCB, rrtype.HTTPS:
		return unpackSVCB(t, u, rdlen)
	case rrtype.CAA:
		return unpackCAA(u, rdlen)
	case rrtype.DNSKEY:
		return unpackDNSKEY(u, rdlen)
	case rrtype.DS:
		return unpackDS(u, rdlen)
	case rrtype.RRSIG:
		return unpackRRSIG(u, rdlen)
	case rrtype.NSEC:
		return unpackNSEC(u, rdlen)
	case rrtype.NSEC3:
		return unpackNSEC3(u, rdlen)
	case rrtype.NSEC3PARAM:
		return unpackNSEC3PARAM(u, rdlen)
	case rrtype.SRV:
		return unpackSRV(u, rdlen)
	case rrtype.NAPTR:
		return unpackNAPTR(u, rdlen)
	case rrtype.RP:
		return unpackRP(u, rdlen)
	case rrtype.AFSDB:
		return unpackAFSDB(u, rdlen)
	case rrtype.X25:
		return unpackX25(u, rdlen)
	case rrtype.ISDN:
		return unpackISDN(u, rdlen)
	case rrtype.RT:
		return unpackRT(u, rdlen)
	case rrtype.NSAP:
		return unpackNSAP(u, rdlen)
	case rrtype.NSAPPTR:
		return unpackNSAPPTR(u, rdlen)
	case rrtype.LOC:
		return unpackLOC(u, rdlen)
	case rrtype.APL:
		return unpackAPL(u, rdlen)
	case rrtype.IPSECKEY:
		return unpackIPSECKEY(u, rdlen)
	case rrtype.DHCID:
		return unpackDHCID(u, rdlen)
	case rrtype.HIP:
		return unpackHIP(u, rdlen)
	case rrtype.NID:
		return unpackNID(u, rdlen)
	case rrtype.L32:
		return unpackL32(u, rdlen)
	case rrtype.L64:
		return unpackL64(u, rdlen)
	case rrtype.LP:
		return unpackLP(u, rdlen)
	case rrtype.EUI48:
		return unpackEUI48(u, rdlen)
	case rrtype.EUI64:
		return unpackEUI64(u, rdlen)
	case rrtype.URI:
		return unpackURI(u, rdlen)
	case rrtype.ZONEMD:
		return unpackZONEMD(u, rdlen)
	case rrtype.RESINFO:
		return unpackRESINFO(u, rdlen)
	case rrtype.SPF:
		return unpackSPF(u, rdlen)
	case rrtype.SSHFP:
		return unpackSSHFP(u, rdlen)
	case rrtype.TLSA:
		return unpackTLSA(u, rdlen)
	case rrtype.SMIMEA:
		return unpackSMIMEA(u, rdlen)
	case rrtype.CSYNC:
		return unpackCSYNC(u, rdlen)
	case rrtype.DNAME:
		return unpackDNAME(u, rdlen)
	case rrtype.HINFO:
		return unpackHINFO(u, rdlen)
	case rrtype.KX:
		return unpackKX(u, rdlen)
	case rrtype.CDS:
		return unpackCDS(u, rdlen)
	case rrtype.CDNSKEY:
		return unpackCDNSKEY(u, rdlen)
	case rrtype.OPENPGPKEY:
		return unpackOPENPGPKEY(u, rdlen)
	case rrtype.CERT:
		return unpackCERT(u, rdlen)
	case rrtype.AMTRELAY:
		return unpackAMTRELAY(u, rdlen)
	case rrtype.TKEY:
		return unpackTKEY(u, rdlen)
	default:
		b, err := u.Bytes(rdlen)
		if err != nil {
			return nil, err
		}
		// copy because u.Bytes aliases the underlying message
		cp := make([]byte, len(b))
		copy(cp, b)
		return Unknown{typ: t, data: cp}, nil
	}
}
