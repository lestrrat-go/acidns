package rdata

import (
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// CDS is the Child DS rdata (RFC 7344 §3.1). Wire format is identical to
// DS (RFC 4034 §5). RFC 8078 §4 reserves the (algorithm 0, digest-type 0,
// single-byte 0x00 digest) tuple as a sentinel meaning "delete the parent
// DS RRset"; constructors and codecs accept this form unchanged.
type CDS struct {
	keyTag    uint16
	algorithm DNSSECAlgorithm
	digestT   DSDigestType
	digest    []byte
}

func (CDS) Type() rrtype.Type            { return rrtype.CDS }
func (CDS) typedRData()                  {}
func (d CDS) KeyTag() uint16             { return d.keyTag }
func (d CDS) Algorithm() DNSSECAlgorithm { return d.algorithm }
func (d CDS) DigestType() DSDigestType   { return d.digestT }
func (d CDS) Digest() []byte             { return d.digest }
func (d CDS) Pack(p *wirebb.Packer) {
	p.Uint16(d.keyTag)
	p.Uint8(uint8(d.algorithm))
	p.Uint8(uint8(d.digestT))
	p.Raw(d.digest)
}

// NewCDS returns a CDS rdata.
func NewCDS(keyTag uint16, alg DNSSECAlgorithm, dt DSDigestType, digest []byte) CDS {
	cp := make([]byte, len(digest))
	copy(cp, digest)
	return CDS{keyTag: keyTag, algorithm: alg, digestT: dt, digest: cp}
}

func unpackCDS(u *wirebb.Unpacker, rdlen int) (CDS, error) {
	var zero CDS
	end := u.Off() + rdlen
	tag, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	alg, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	dt, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	dig, err := u.Bytes(end - u.Off())
	if err != nil {
		return zero, err
	}
	cp := make([]byte, len(dig))
	copy(cp, dig)
	return CDS{keyTag: tag, algorithm: DNSSECAlgorithm(alg), digestT: DSDigestType(dt), digest: cp}, nil
}

// CDNSKEY is the Child DNSKEY rdata (RFC 7344 §3.2). Wire format is
// identical to DNSKEY (RFC 4034 §2).
type CDNSKEY struct {
	flags     uint16
	protocol  uint8
	algorithm DNSSECAlgorithm
	pubkey    []byte
}

func (CDNSKEY) Type() rrtype.Type            { return rrtype.CDNSKEY }
func (CDNSKEY) typedRData()                  {}
func (k CDNSKEY) Flags() uint16              { return k.flags }
func (k CDNSKEY) Protocol() uint8            { return k.protocol }
func (k CDNSKEY) Algorithm() DNSSECAlgorithm { return k.algorithm }
func (k CDNSKEY) PublicKey() []byte          { return k.pubkey }
func (k CDNSKEY) Pack(p *wirebb.Packer) {
	p.Uint16(k.flags)
	p.Uint8(k.protocol)
	p.Uint8(uint8(k.algorithm))
	p.Raw(k.pubkey)
}

// NewCDNSKEY returns a CDNSKEY rdata.
func NewCDNSKEY(flags uint16, protocol uint8, algorithm DNSSECAlgorithm, pubkey []byte) CDNSKEY {
	cp := make([]byte, len(pubkey))
	copy(cp, pubkey)
	return CDNSKEY{flags: flags, protocol: protocol, algorithm: algorithm, pubkey: cp}
}

func unpackCDNSKEY(u *wirebb.Unpacker, rdlen int) (CDNSKEY, error) {
	var zero CDNSKEY
	end := u.Off() + rdlen
	flags, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	proto, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	alg, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	pk, err := u.Bytes(end - u.Off())
	if err != nil {
		return zero, err
	}
	cp := make([]byte, len(pk))
	copy(cp, pk)
	return CDNSKEY{flags: flags, protocol: proto, algorithm: DNSSECAlgorithm(alg), pubkey: cp}, nil
}
