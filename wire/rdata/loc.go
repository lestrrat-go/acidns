package rdata

import (
	"fmt"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// LOC is the location rdata (RFC 1876).
//
// Wire layout (16 bytes):
//
//	VERSION (1) | SIZE (1) | HORIZ PRE (1) | VERT PRE (1)
//	LATITUDE (4) | LONGITUDE (4) | ALTITUDE (4)
//
// Size and precision fields are encoded as one byte where the high nibble is
// the base (1–9) and the low nibble is the power of ten (0–9), expressing
// the value in centimetres.
type LOC struct {
	version  uint8
	size     uint8
	horizPre uint8
	vertPre  uint8
	lat      uint32
	lon      uint32
	alt      uint32
}

func (LOC) Type() rrtype.Type   { return rrtype.LOC }
func (LOC) typedRData()         {}
func (l LOC) Version() uint8    { return l.version }
func (l LOC) Size() uint8       { return l.size }
func (l LOC) HorizPre() uint8   { return l.horizPre }
func (l LOC) VertPre() uint8    { return l.vertPre }
func (l LOC) Latitude() uint32  { return l.lat }
func (l LOC) Longitude() uint32 { return l.lon }
func (l LOC) Altitude() uint32  { return l.alt }
func (l LOC) Pack(p *wirebb.Packer) {
	p.Uint8(l.version)
	p.Uint8(l.size)
	p.Uint8(l.horizPre)
	p.Uint8(l.vertPre)
	p.Uint32(l.lat)
	p.Uint32(l.lon)
	p.Uint32(l.alt)
}

// NewLOC returns a LOC rdata. Version is 0 per RFC 1876.
func NewLOC(version, size, horizPre, vertPre uint8, latitude, longitude, altitude uint32) LOC {
	return LOC{
		version: version, size: size, horizPre: horizPre, vertPre: vertPre,
		lat: latitude, lon: longitude, alt: altitude,
	}
}

func unpackLOC(u *wirebb.Unpacker, rdlen int) (LOC, error) {
	var zero LOC
	if rdlen != 16 {
		return zero, fmt.Errorf("%w: LOC rdlen=%d, want 16", ErrInvalidRData, rdlen)
	}
	v, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	sz, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	hp, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	vp, err := u.Uint8()
	if err != nil {
		return zero, err
	}
	lat, err := u.Uint32()
	if err != nil {
		return zero, err
	}
	lon, err := u.Uint32()
	if err != nil {
		return zero, err
	}
	alt, err := u.Uint32()
	if err != nil {
		return zero, err
	}
	return LOC{version: v, size: sz, horizPre: hp, vertPre: vp, lat: lat, lon: lon, alt: alt}, nil
}
