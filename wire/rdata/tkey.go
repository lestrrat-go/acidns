package rdata

import (
	"fmt"
	"time"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// TKEYMode identifies the key-establishment mode used by a TKEY rdata
// (RFC 2930 §2.5, IANA "DNS TKEY Modes" registry).
type TKEYMode uint16

const (
	TKEYModeReserved       TKEYMode = 0
	TKEYModeServerAssign   TKEYMode = 1
	TKEYModeDH             TKEYMode = 2
	TKEYModeGSSAPI         TKEYMode = 3 // RFC 3645
	TKEYModeResolverAssign TKEYMode = 4
	TKEYModeKeyDeletion    TKEYMode = 5
)

// TKEY is the transaction-key rdata (RFC 2930). The wire format places
// the algorithm name uncompressed (RFC 3597 §4) followed by inception,
// expiration, mode, error, then length-prefixed key-data and other-data
// octet streams.
type TKEY struct {
	algorithm wirebb.Name
	inception uint32
	expire    uint32
	mode      TKEYMode
	errCode   uint16
	keyData   []byte
	otherData []byte
}

func (TKEY) Type() rrtype.Type        { return rrtype.TKEY }
func (TKEY) typedRData()              {}
func (t TKEY) Algorithm() wirebb.Name { return t.algorithm }
func (t TKEY) Inception() time.Time   { return time.Unix(int64(t.inception), 0).UTC() }
func (t TKEY) Expiration() time.Time  { return time.Unix(int64(t.expire), 0).UTC() }
func (t TKEY) Mode() TKEYMode         { return t.mode }
func (t TKEY) Error() uint16          { return t.errCode }
func (t TKEY) KeyData() []byte        { return t.keyData }
func (t TKEY) OtherData() []byte      { return t.otherData }
func (t TKEY) Pack(p *wirebb.Packer) {
	p.NameUncompressed(t.algorithm)
	p.Uint32(t.inception)
	p.Uint32(t.expire)
	p.Uint16(uint16(t.mode))
	p.Uint16(t.errCode)
	p.Uint16(uint16(len(t.keyData)))
	p.Raw(t.keyData)
	p.Uint16(uint16(len(t.otherData)))
	p.Raw(t.otherData)
}

// NewTKEY returns a TKEY rdata. keyData and otherData must each be
// ≤ 65535 bytes; the caller's slices are copied.
func NewTKEY(algorithm wirebb.Name, inception, expiration time.Time,
	mode TKEYMode, errCode uint16, keyData, otherData []byte) (TKEY, error) {
	var zero TKEY
	if len(keyData) > 0xffff {
		return zero, fmt.Errorf("%w: TKEY key-data exceeds 65535 bytes", ErrInvalidRData)
	}
	if len(otherData) > 0xffff {
		return zero, fmt.Errorf("%w: TKEY other-data exceeds 65535 bytes", ErrInvalidRData)
	}
	kd := make([]byte, len(keyData))
	copy(kd, keyData)
	od := make([]byte, len(otherData))
	copy(od, otherData)
	return TKEY{
		algorithm: algorithm,
		inception: uint32(inception.Unix()),
		expire:    uint32(expiration.Unix()),
		mode:      mode,
		errCode:   errCode,
		keyData:   kd,
		otherData: od,
	}, nil
}

func unpackTKEY(u *wirebb.Unpacker, rdlen int) (TKEY, error) {
	var zero TKEY
	end := u.Off() + rdlen
	alg, err := u.UncompressedNameInRange(end)
	if err != nil {
		return zero, err
	}
	inc, err := u.Uint32()
	if err != nil {
		return zero, err
	}
	exp, err := u.Uint32()
	if err != nil {
		return zero, err
	}
	mode, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	ec, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	klen, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	if u.Off()+int(klen) > end {
		return zero, fmt.Errorf("%w: TKEY key-data length %d exceeds rdlen", ErrInvalidRData, klen)
	}
	kd, err := u.Bytes(int(klen))
	if err != nil {
		return zero, err
	}
	kdcp := make([]byte, len(kd))
	copy(kdcp, kd)
	olen, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	if u.Off()+int(olen) > end {
		return zero, fmt.Errorf("%w: TKEY other-data length %d exceeds rdlen", ErrInvalidRData, olen)
	}
	od, err := u.Bytes(int(olen))
	if err != nil {
		return zero, err
	}
	odcp := make([]byte, len(od))
	copy(odcp, od)
	return TKEY{
		algorithm: alg, inception: inc, expire: exp,
		mode: TKEYMode(mode), errCode: ec,
		keyData: kdcp, otherData: odcp,
	}, nil
}
