package rdata

import (
	"fmt"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// TXT is the text rdata (RFC 1035 §3.3.14). The wire format is one or more
// length-prefixed character strings; this struct surfaces them as a slice.
type TXT struct{ strs []string }

func (TXT) Type() rrtype.Type   { return rrtype.TXT }
func (TXT) typedRData()         {}
func (t TXT) Strings() []string { return t.strs }
func (t TXT) Pack(p *wirebb.Packer) {
	for _, s := range t.strs {
		// length already validated at construction
		_ = p.CharString([]byte(s))
	}
}

// NewTXT returns a TXT rdata. Each input string must fit in a single
// character string (≤ 255 bytes); longer inputs return an error rather than
// being silently split.
func NewTXT(strs ...string) (TXT, error) {
	var zero TXT
	for i, s := range strs {
		if len(s) > 255 {
			return zero, fmt.Errorf("%w: TXT string %d exceeds 255 bytes", ErrInvalidRData, i)
		}
	}
	cp := make([]string, len(strs))
	copy(cp, strs)
	return TXT{strs: cp}, nil
}

func unpackTXT(u *wirebb.Unpacker, rdlen int) (TXT, error) {
	var zero TXT
	end := u.Off() + rdlen
	var out []string
	for u.Off() < end {
		s, err := u.CharString()
		if err != nil {
			return zero, err
		}
		out = append(out, string(s))
	}
	return TXT{strs: out}, nil
}
