package rdata

import (
	"fmt"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// HINFO is the host information rdata (RFC 1035 §3.3.2). Two
// character-strings: CPU and OS.
type HINFO struct {
	cpu string
	os  string
}

func (HINFO) Type() rrtype.Type { return rrtype.HINFO }
func (HINFO) typedRData()       {}
func (h HINFO) CPU() string     { return h.cpu }
func (h HINFO) OS() string      { return h.os }
func (h HINFO) Pack(p *wirebb.Packer) {
	_ = p.CharString([]byte(h.cpu))
	_ = p.CharString([]byte(h.os))
}

// NewHINFO returns a HINFO rdata. CPU and OS must each be ≤ 255 bytes.
func NewHINFO(cpu, os string) (HINFO, error) {
	var zero HINFO
	if len(cpu) > 255 {
		return zero, fmt.Errorf("%w: HINFO CPU exceeds 255 bytes", ErrInvalidRData)
	}
	if len(os) > 255 {
		return zero, fmt.Errorf("%w: HINFO OS exceeds 255 bytes", ErrInvalidRData)
	}
	return HINFO{cpu: cpu, os: os}, nil
}

func unpackHINFO(u *wirebb.Unpacker, rdlen int) (HINFO, error) {
	var zero HINFO
	end := u.Off() + rdlen
	cpu, err := u.CharStringInRange(end)
	if err != nil {
		return zero, err
	}
	os, err := u.CharStringInRange(end)
	if err != nil {
		return zero, err
	}
	return HINFO{cpu: string(cpu), os: string(os)}, nil
}
