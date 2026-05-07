package rdata

import (
	"fmt"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// URI is the URI rdata (RFC 7553).
//
// Wire layout:
//
//	Priority (uint16) | Weight (uint16) | Target (rest of rdata, raw bytes)
//
// The target is NOT length-prefixed: its length is rdlen − 4. RFC 7553 §4.5
// requires the target to be at least 1 byte.
type URI struct {
	priority uint16
	weight   uint16
	target   string
}

func (URI) Type() rrtype.Type  { return rrtype.URI }
func (URI) typedRData()        {}
func (u URI) Priority() uint16 { return u.priority }
func (u URI) Weight() uint16   { return u.weight }
func (u URI) Target() string   { return u.target }
func (u URI) Pack(p *wirebb.Packer) {
	p.Uint16(u.priority)
	p.Uint16(u.weight)
	p.Raw([]byte(u.target))
}

// NewURI returns a URI rdata. The target must be non-empty.
func NewURI(priority, weight uint16, target string) (URI, error) {
	var zero URI
	if target == "" {
		return zero, fmt.Errorf("%w: URI target must be non-empty", ErrInvalidRData)
	}
	return URI{priority: priority, weight: weight, target: target}, nil
}

func unpackURI(u *wirebb.Unpacker, rdlen int) (URI, error) {
	var zero URI
	if rdlen < 5 {
		return zero, fmt.Errorf("%w: URI rdlen=%d, want >=5", ErrInvalidRData, rdlen)
	}
	pr, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	w, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	t, err := u.Bytes(rdlen - 4)
	if err != nil {
		return zero, err
	}
	return URI{priority: pr, weight: w, target: string(t)}, nil
}
