package rdata

import (
	"fmt"

	"github.com/lestrrat-go/acidns/dnsmsg/internal/wire"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
)

// RESINFO is the DNS Resolver Information rdata (RFC 9606). Wire format
// matches TXT: a sequence of <character-string>s.
type RESINFO interface {
	RData
	Strings() []string
}

type resinfo struct{ strs []string }

func (resinfo) Type() rrtype.Type   { return rrtype.RESINFO }
func (r resinfo) Strings() []string { return r.strs }
func (r resinfo) Pack(p *wire.Packer) {
	for _, s := range r.strs {
		_ = p.CharString([]byte(s))
	}
}

// NewRESINFO returns a RESINFO rdata. Each string must be ≤ 255 bytes.
func NewRESINFO(strs ...string) (RESINFO, error) {
	for i, s := range strs {
		if len(s) > 255 {
			return nil, fmt.Errorf("%w: RESINFO string %d exceeds 255 bytes", ErrInvalidRData, i)
		}
	}
	cp := make([]string, len(strs))
	copy(cp, strs)
	return resinfo{strs: cp}, nil
}

func unpackRESINFO(u *wire.Unpacker, rdlen int) (RESINFO, error) {
	end := u.Off() + rdlen
	var out []string
	for u.Off() < end {
		s, err := u.CharString()
		if err != nil {
			return nil, err
		}
		out = append(out, string(s))
	}
	return resinfo{strs: out}, nil
}
