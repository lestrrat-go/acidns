package rdata

import (
	"fmt"

	"github.com/lestrrat-go/acidns/dnsmsg/internal/wire"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
)

// TXT is the text rdata (RFC 1035 §3.3.14). The wire format is one or more
// length-prefixed character strings; this interface surfaces them as a slice.
type TXT interface {
	RData
	Strings() []string
}

type txt struct{ strs []string }

func (txt) Type() rrtype.Type   { return rrtype.TXT }
func (t txt) Strings() []string { return t.strs }
func (t txt) Pack(p *wire.Packer) {
	for _, s := range t.strs {
		// length already validated at construction
		_ = p.CharString([]byte(s))
	}
}

// NewTXT returns a TXT rdata. Each input string must fit in a single
// character string (≤ 255 bytes); longer inputs return an error rather than
// being silently split.
func NewTXT(strs ...string) (TXT, error) {
	for i, s := range strs {
		if len(s) > 255 {
			return nil, fmt.Errorf("%w: TXT string %d exceeds 255 bytes", ErrInvalidRData, i)
		}
	}
	cp := make([]string, len(strs))
	copy(cp, strs)
	return txt{strs: cp}, nil
}

func unpackTXT(u *wire.Unpacker, rdlen int) (TXT, error) {
	end := u.Off() + rdlen
	var out []string
	for u.Off() < end {
		s, err := u.CharString()
		if err != nil {
			return nil, err
		}
		out = append(out, string(s))
	}
	return txt{strs: out}, nil
}
