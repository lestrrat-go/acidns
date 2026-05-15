package rdata

import (
	"fmt"
	"net/netip"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// IPSECKEYGatewayType identifies the gateway encoding used in an IPSECKEY
// rdata (RFC 4025 §2.3).
type IPSECKEYGatewayType uint8

const (
	IPSECKEYGatewayNone IPSECKEYGatewayType = 0
	IPSECKEYGatewayIPv4 IPSECKEYGatewayType = 1
	IPSECKEYGatewayIPv6 IPSECKEYGatewayType = 2
	IPSECKEYGatewayName IPSECKEYGatewayType = 3
)

// IPSECKEYAlgorithm identifies the public-key algorithm in an IPSECKEY rdata
// (RFC 4025 §2.4 plus extensions).
type IPSECKEYAlgorithm uint8

const (
	IPSECKEYAlgNone  IPSECKEYAlgorithm = 0
	IPSECKEYAlgDSA   IPSECKEYAlgorithm = 1
	IPSECKEYAlgRSA   IPSECKEYAlgorithm = 2
	IPSECKEYAlgECDSA IPSECKEYAlgorithm = 3
)

// IPSECKEY is the IPsec keying material rdata (RFC 4025).
//
// GatewayAddr is set when GatewayType is IPv4 or IPv6; GatewayName is set
// when GatewayType is Name; both are zero-valued when GatewayType is None.
type IPSECKEY struct {
	prec   uint8
	gt     IPSECKEYGatewayType
	alg    IPSECKEYAlgorithm
	gwAddr netip.Addr
	gwName wirebb.Name
	pubkey []byte
}

func (IPSECKEY) Type() rrtype.Type                  { return rrtype.IPSECKEY }
func (IPSECKEY) typedRData()                        {}
func (k IPSECKEY) Precedence() uint8                { return k.prec }
func (k IPSECKEY) GatewayType() IPSECKEYGatewayType { return k.gt }
func (k IPSECKEY) Algorithm() IPSECKEYAlgorithm     { return k.alg }
func (k IPSECKEY) GatewayAddr() netip.Addr          { return k.gwAddr }
func (k IPSECKEY) GatewayName() wirebb.Name         { return k.gwName }
func (k IPSECKEY) PublicKey() []byte                { return k.pubkey }
func (k IPSECKEY) Pack(p *wirebb.Packer) {
	p.Uint8(k.prec)
	p.Uint8(uint8(k.gt))
	p.Uint8(uint8(k.alg))
	switch k.gt {
	case IPSECKEYGatewayIPv4:
		b := k.gwAddr.As4()
		p.Raw(b[:])
	case IPSECKEYGatewayIPv6:
		b := k.gwAddr.As16()
		p.Raw(b[:])
	case IPSECKEYGatewayName:
		// RFC 4025 §2.5: gateway name MUST NOT be compressed.
		p.NameUncompressed(k.gwName)
	}
	p.Raw(k.pubkey)
}

// NewIPSECKEYNoGateway returns an IPSECKEY rdata with gateway type 0.
func NewIPSECKEYNoGateway(prec uint8, alg IPSECKEYAlgorithm, pubkey []byte) IPSECKEY {
	cp := make([]byte, len(pubkey))
	copy(cp, pubkey)
	return IPSECKEY{prec: prec, gt: IPSECKEYGatewayNone, alg: alg, pubkey: cp}
}

// NewIPSECKEYAddr returns an IPSECKEY rdata whose gateway is an IPv4 or IPv6
// address.
func NewIPSECKEYAddr(prec uint8, alg IPSECKEYAlgorithm, addr netip.Addr, pubkey []byte) (IPSECKEY, error) {
	var zero IPSECKEY
	gt := IPSECKEYGatewayIPv4
	if addr.Is6() {
		gt = IPSECKEYGatewayIPv6
	} else if !addr.Is4() {
		return zero, fmt.Errorf("%w: IPSECKEY gateway address must be IPv4 or IPv6", ErrInvalidRData)
	}
	cp := make([]byte, len(pubkey))
	copy(cp, pubkey)
	return IPSECKEY{prec: prec, gt: gt, alg: alg, gwAddr: addr, pubkey: cp}, nil
}

// NewIPSECKEYName returns an IPSECKEY rdata whose gateway is a domain
// name. Returns [ErrInvalidRData] when name is the zero name; mirrors
// [NewIPSECKEYAddr]'s validation surface.
func NewIPSECKEYName(prec uint8, alg IPSECKEYAlgorithm, name wirebb.Name, pubkey []byte) (IPSECKEY, error) {
	if !name.IsValid() {
		return IPSECKEY{}, fmt.Errorf("%w: IPSECKEY gateway name is invalid", ErrInvalidRData)
	}
	cp := make([]byte, len(pubkey))
	copy(cp, pubkey)
	return IPSECKEY{prec: prec, gt: IPSECKEYGatewayName, alg: alg, gwName: name, pubkey: cp}, nil
}
func unpackIPSECKEY(u *wirebb.Unpacker, rdlen int) (IPSECKEY, error) {
	var zero IPSECKEY
	end := u.Off() + rdlen
	prec, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	gt, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	alg, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	k := IPSECKEY{prec: prec, gt: IPSECKEYGatewayType(gt), alg: IPSECKEYAlgorithm(alg)}
	switch IPSECKEYGatewayType(gt) {
	case IPSECKEYGatewayNone:
		// no gateway
	case IPSECKEYGatewayIPv4:
		if u.Off()+4 > end {
			return zero, fmt.Errorf("%w: IPSECKEY IPv4 gateway exceeds rdlen", ErrInvalidRData)
		}
		b, err := u.Bytes(4)
		if err != nil {
			return zero, err
		}
		k.gwAddr = netip.AddrFrom4([4]byte(b))
	case IPSECKEYGatewayIPv6:
		if u.Off()+16 > end {
			return zero, fmt.Errorf("%w: IPSECKEY IPv6 gateway exceeds rdlen", ErrInvalidRData)
		}
		b, err := u.Bytes(16)
		if err != nil {
			return zero, err
		}
		k.gwAddr = netip.AddrFrom16([16]byte(b))
	case IPSECKEYGatewayName:
		n, err := u.UncompressedName(end - u.Off())
		if err != nil {
			return zero, err
		}
		k.gwName = n
	default:
		return zero, fmt.Errorf("%w: IPSECKEY unknown gateway type %d", ErrInvalidRData, gt)
	}
	remaining := end - u.Off()
	if remaining < 0 {
		return zero, fmt.Errorf("%w: IPSECKEY gateway exceeds rdlen", ErrInvalidRData)
	}
	pk, err := u.Bytes(remaining)
	if err != nil {
		return zero, err
	}
	cp := make([]byte, len(pk))
	copy(cp, pk)
	k.pubkey = cp
	return k, nil
}
