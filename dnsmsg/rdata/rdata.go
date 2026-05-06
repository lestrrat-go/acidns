// Package rdata defines the typed resource record payloads carried inside a
// DNS message. Public types are interfaces with strongly-typed accessors;
// constructors return concrete unexported implementations.
package rdata

import (
	"errors"
	"fmt"

	"github.com/lestrrat-go/acidns/dnsmsg/internal/wire"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
)

// ErrInvalidRData is returned when an rdata payload cannot be encoded or
// decoded against the rules of its type.
var ErrInvalidRData = errors.New("rdata: invalid")

// RData is the common interface implemented by every rdata payload. Type
// reports the RR type; Pack appends the rdata wire encoding to p, including
// the 16-bit length prefix is NOT this method's responsibility — it is
// written by dnsmsg, which back-fills the length after Pack returns.
type RData interface {
	Type() rrtype.Type
	Pack(p *wire.Packer)
}

// Unpack reads rdlen bytes of rdata of type t from u and returns a typed
// RData value. Unknown types are returned as Unknown.
func Unpack(t rrtype.Type, u *wire.Unpacker, rdlen int) (RData, error) {
	if rdlen < 0 || u.Remaining() < rdlen {
		return nil, fmt.Errorf("%w: rdlen %d exceeds remaining %d", ErrInvalidRData, rdlen, u.Remaining())
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

func unpackTyped(t rrtype.Type, u *wire.Unpacker, rdlen int) (RData, error) {
	switch t {
	case rrtype.A:
		return unpackA(u)
	case rrtype.AAAA:
		return unpackAAAA(u)
	case rrtype.CNAME:
		return unpackCNAME(u)
	case rrtype.NS:
		return unpackNS(u)
	case rrtype.PTR:
		return unpackPTR(u)
	case rrtype.MX:
		return unpackMX(u)
	case rrtype.TXT:
		return unpackTXT(u, rdlen)
	case rrtype.SOA:
		return unpackSOA(u)
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
	default:
		b, err := u.Bytes(rdlen)
		if err != nil {
			return nil, err
		}
		// copy because u.Bytes aliases the underlying message
		cp := make([]byte, len(b))
		copy(cp, b)
		return &unknown{typ: t, data: cp}, nil
	}
}
