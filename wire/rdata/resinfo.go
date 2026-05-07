package rdata

import (
	"fmt"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// RESINFO is the DNS Resolver Information rdata (RFC 9606). Wire format
// matches TXT: a sequence of <character-string>s.
type RESINFO struct{ strs []string }

func (RESINFO) Type() rrtype.Type   { return rrtype.RESINFO }
func (RESINFO) typedRData()         {}
func (r RESINFO) Strings() []string { return r.strs }
func (r RESINFO) Pack(p *wirebb.Packer) {
	for _, s := range r.strs {
		_ = p.CharString([]byte(s))
	}
}

// NewRESINFO returns a RESINFO rdata. Each string must be ≤ 255 bytes.
func NewRESINFO(strs ...string) (RESINFO, error) {
	var zero RESINFO
	for i, s := range strs {
		if len(s) > 255 {
			return zero, fmt.Errorf("%w: RESINFO string %d exceeds 255 bytes", ErrInvalidRData, i)
		}
	}
	cp := make([]string, len(strs))
	copy(cp, strs)
	return RESINFO{strs: cp}, nil
}

func unpackRESINFO(u *wirebb.Unpacker, rdlen int) (RESINFO, error) {
	var zero RESINFO
	end := u.Off() + rdlen
	var out []string
	for u.Off() < end {
		s, err := u.CharString()
		if err != nil {
			return zero, err
		}
		out = append(out, string(s))
	}
	return RESINFO{strs: out}, nil
}
