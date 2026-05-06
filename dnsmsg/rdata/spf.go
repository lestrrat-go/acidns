package rdata

import (
	"fmt"

	"github.com/lestrrat-go/acidns/dnsmsg/internal/wire"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
)

// SPF is the Sender Policy Framework rdata (RFC 4408 §3.1). Wire format
// matches TXT: a sequence of <character-string>s. SPF was deprecated in
// favour of TXT records by RFC 7208 but remains assigned as type 99.
type SPF interface {
	RData
	Strings() []string
}

type spf struct{ strs []string }

func (spf) Type() rrtype.Type   { return rrtype.SPF }
func (s spf) Strings() []string { return s.strs }
func (s spf) Pack(p *wire.Packer) {
	for _, str := range s.strs {
		_ = p.CharString([]byte(str))
	}
}

// NewSPF returns an SPF rdata. Each string must be ≤ 255 bytes.
func NewSPF(strs ...string) (SPF, error) {
	for i, str := range strs {
		if len(str) > 255 {
			return nil, fmt.Errorf("%w: SPF string %d exceeds 255 bytes", ErrInvalidRData, i)
		}
	}
	cp := make([]string, len(strs))
	copy(cp, strs)
	return spf{strs: cp}, nil
}

func unpackSPF(u *wire.Unpacker, rdlen int) (SPF, error) {
	end := u.Off() + rdlen
	var out []string
	for u.Off() < end {
		s, err := u.CharString()
		if err != nil {
			return nil, err
		}
		out = append(out, string(s))
	}
	return spf{strs: out}, nil
}
