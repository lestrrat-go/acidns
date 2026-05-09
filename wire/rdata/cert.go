package rdata

import (
	"fmt"
	"slices"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// CERTType identifies the certificate format carried in a CERT rdata
// (RFC 4398 §2.1, IANA "DNS CERT Types" registry).
type CERTType uint16

const (
	CERTTypePKIX    CERTType = 1 // X.509 as per PKIX
	CERTTypeSPKI    CERTType = 2 // SPKI certificate
	CERTTypePGP     CERTType = 3 // OpenPGP packet
	CERTTypeIPKIX   CERTType = 4 // The URL of an X.509 data object
	CERTTypeISPKI   CERTType = 5 // The URL of an SPKI certificate
	CERTTypeIPGP    CERTType = 6 // The fingerprint and URL of an OpenPGP packet
	CERTTypeACPKIX  CERTType = 7 // Attribute Certificate
	CERTTypeIACPKIX CERTType = 8 // The URL of an Attribute Certificate
	CERTTypeURI     CERTType = 253
	CERTTypeOID     CERTType = 254
)

// CERT is the certificate rdata (RFC 4398 §2). The certificate algorithm
// shares the IANA DNSSEC Algorithm Numbers registry with DNSKEY.
type CERT struct {
	certType  CERTType
	keyTag    uint16
	algorithm DNSSECAlgorithm
	cert      []byte
}

func (CERT) Type() rrtype.Type            { return rrtype.CERT }
func (CERT) typedRData()                  {}
func (c CERT) CertType() CERTType         { return c.certType }
func (c CERT) KeyTag() uint16             { return c.keyTag }
func (c CERT) Algorithm() DNSSECAlgorithm { return c.algorithm }
func (c CERT) Certificate() []byte        { return slices.Clone(c.cert) }
func (c CERT) Pack(p *wirebb.Packer) {
	p.Uint16(uint16(c.certType))
	p.Uint16(c.keyTag)
	p.Uint8(uint8(c.algorithm))
	p.Raw(c.cert)
}

// NewCERT returns a CERT rdata.
func NewCERT(certType CERTType, keyTag uint16, alg DNSSECAlgorithm, cert []byte) CERT {
	cp := make([]byte, len(cert))
	copy(cp, cert)
	return CERT{certType: certType, keyTag: keyTag, algorithm: alg, cert: cp}
}

func unpackCERT(u *wirebb.Unpacker, rdlen int) (CERT, error) {
	var zero CERT
	if rdlen < 5 {
		return zero, fmt.Errorf("%w: CERT rdlen %d < 5", ErrInvalidRData, rdlen)
	}
	end := u.Off() + rdlen
	ct, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	tag, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	alg, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	cert, err := u.Bytes(end - u.Off())
	if err != nil {
		return zero, err
	}
	cp := make([]byte, len(cert))
	copy(cp, cert)
	return CERT{certType: CERTType(ct), keyTag: tag, algorithm: DNSSECAlgorithm(alg), cert: cp}, nil
}
