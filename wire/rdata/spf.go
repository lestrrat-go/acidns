package rdata

import (
	"fmt"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// SPF is the Sender Policy Framework rdata (RFC 4408 §3.1). Wire format
// matches TXT: a sequence of <character-string>s. SPF was deprecated in
// favour of TXT records by RFC 7208 but remains assigned as type 99.
type SPF struct{ strs []string }

func (SPF) Type() rrtype.Type   { return rrtype.SPF }
func (SPF) typedRData()         {}
func (s SPF) Strings() []string { return s.strs }
func (s SPF) Pack(p *wirebb.Packer) {
	for _, str := range s.strs {
		_ = p.CharString([]byte(str))
	}
}

// NewSPF returns an SPF rdata. Each string must be ≤ 255 bytes.
func NewSPF(strs ...string) (SPF, error) {
	var zero SPF
	for i, str := range strs {
		if len(str) > 255 {
			return zero, fmt.Errorf("%w: SPF string %d exceeds 255 bytes", ErrInvalidRData, i)
		}
	}
	cp := make([]string, len(strs))
	copy(cp, strs)
	return SPF{strs: cp}, nil
}

func unpackSPF(u *wirebb.Unpacker, rdlen int) (SPF, error) {
	var zero SPF
	end := u.Off() + rdlen
	var out []string
	for u.Off() < end {
		s, err := u.CharString()
		if err != nil {
			return zero, err
		}
		out = append(out, string(s))
	}
	return SPF{strs: out}, nil
}
