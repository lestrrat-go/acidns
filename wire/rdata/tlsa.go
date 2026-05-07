package rdata

import (
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// TLSAUsage names a TLSA Certificate Usage (RFC 6698 §2.1.1).
type TLSAUsage uint8

const (
	TLSAUsagePKIXTA TLSAUsage = 0 // CA constraint
	TLSAUsagePKIXEE TLSAUsage = 1 // service certificate constraint
	TLSAUsageDANETA TLSAUsage = 2 // trust-anchor assertion
	TLSAUsageDANEEE TLSAUsage = 3 // domain-issued certificate
)

// TLSASelector names a TLSA Selector (RFC 6698 §2.1.2).
type TLSASelector uint8

const (
	TLSASelectorFullCert TLSASelector = 0
	TLSASelectorSPKI     TLSASelector = 1 // SubjectPublicKeyInfo
)

// TLSAMatchingType names a TLSA Matching Type (RFC 6698 §2.1.3).
type TLSAMatchingType uint8

const (
	TLSAMatchingFull   TLSAMatchingType = 0
	TLSAMatchingSHA256 TLSAMatchingType = 1
	TLSAMatchingSHA512 TLSAMatchingType = 2
)

// TLSA is the TLSA rdata (RFC 6698) — DANE binding of a TLS certificate
// or public-key hash to a domain name.
type TLSA interface {
	RData
	Usage() TLSAUsage
	Selector() TLSASelector
	MatchingType() TLSAMatchingType
	CertificateAssociation() []byte
}

type tlsa struct {
	usage    TLSAUsage
	selector TLSASelector
	matching TLSAMatchingType
	data     []byte
}

func (tlsa) Type() rrtype.Type                { return rrtype.TLSA }
func (t tlsa) Usage() TLSAUsage               { return t.usage }
func (t tlsa) Selector() TLSASelector         { return t.selector }
func (t tlsa) MatchingType() TLSAMatchingType { return t.matching }
func (t tlsa) CertificateAssociation() []byte { return t.data }
func (t tlsa) Pack(p *wirebb.Packer) {
	p.Uint8(uint8(t.usage))
	p.Uint8(uint8(t.selector))
	p.Uint8(uint8(t.matching))
	p.Raw(t.data)
}

// NewTLSA returns a TLSA rdata.
func NewTLSA(usage TLSAUsage, selector TLSASelector, matching TLSAMatchingType, data []byte) TLSA {
	cp := make([]byte, len(data))
	copy(cp, data)
	return tlsa{usage: usage, selector: selector, matching: matching, data: cp}
}

func unpackTLSA(u *wirebb.Unpacker, rdlen int) (TLSA, error) {
	usage, err := u.Uint8()
	if err != nil {
		return nil, err
	}
	selector, err := u.Uint8()
	if err != nil {
		return nil, err
	}
	matching, err := u.Uint8()
	if err != nil {
		return nil, err
	}
	data, err := u.Bytes(rdlen - 3)
	if err != nil {
		return nil, err
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	return tlsa{
		usage: TLSAUsage(usage), selector: TLSASelector(selector),
		matching: TLSAMatchingType(matching), data: cp,
	}, nil
}

// SMIMEA is the SMIMEA rdata (RFC 8162). Wire layout matches TLSA; only
// the RR type code differs.
type SMIMEA interface {
	RData
	Usage() TLSAUsage
	Selector() TLSASelector
	MatchingType() TLSAMatchingType
	CertificateAssociation() []byte
}

type smimea struct {
	usage    TLSAUsage
	selector TLSASelector
	matching TLSAMatchingType
	data     []byte
}

func (smimea) Type() rrtype.Type                { return rrtype.SMIMEA }
func (s smimea) Usage() TLSAUsage               { return s.usage }
func (s smimea) Selector() TLSASelector         { return s.selector }
func (s smimea) MatchingType() TLSAMatchingType { return s.matching }
func (s smimea) CertificateAssociation() []byte { return s.data }
func (s smimea) Pack(p *wirebb.Packer) {
	p.Uint8(uint8(s.usage))
	p.Uint8(uint8(s.selector))
	p.Uint8(uint8(s.matching))
	p.Raw(s.data)
}

// NewSMIMEA returns an SMIMEA rdata.
func NewSMIMEA(usage TLSAUsage, selector TLSASelector, matching TLSAMatchingType, data []byte) SMIMEA {
	cp := make([]byte, len(data))
	copy(cp, data)
	return smimea{usage: usage, selector: selector, matching: matching, data: cp}
}

func unpackSMIMEA(u *wirebb.Unpacker, rdlen int) (SMIMEA, error) {
	usage, err := u.Uint8()
	if err != nil {
		return nil, err
	}
	selector, err := u.Uint8()
	if err != nil {
		return nil, err
	}
	matching, err := u.Uint8()
	if err != nil {
		return nil, err
	}
	data, err := u.Bytes(rdlen - 3)
	if err != nil {
		return nil, err
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	return smimea{
		usage: TLSAUsage(usage), selector: TLSASelector(selector),
		matching: TLSAMatchingType(matching), data: cp,
	}, nil
}
