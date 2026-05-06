package rdata

import (
	"fmt"

	"github.com/lestrrat-go/acidns/dnsmsg/internal/wire"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
)

// URI is the URI rdata (RFC 7553).
//
// Wire layout:
//
//	Priority (uint16) | Weight (uint16) | Target (rest of rdata, raw bytes)
//
// The target is NOT length-prefixed: its length is rdlen − 4. RFC 7553 §4.5
// requires the target to be at least 1 byte.
type URI interface {
	RData
	Priority() uint16
	Weight() uint16
	Target() string
}

type uriR struct {
	priority uint16
	weight   uint16
	target   string
}

func (uriR) Type() rrtype.Type   { return rrtype.URI }
func (u uriR) Priority() uint16  { return u.priority }
func (u uriR) Weight() uint16    { return u.weight }
func (u uriR) Target() string    { return u.target }
func (u uriR) Pack(p *wire.Packer) {
	p.Uint16(u.priority)
	p.Uint16(u.weight)
	p.Raw([]byte(u.target))
}

// NewURI returns a URI rdata. The target must be non-empty.
func NewURI(priority, weight uint16, target string) (URI, error) {
	if target == "" {
		return nil, fmt.Errorf("%w: URI target must be non-empty", ErrInvalidRData)
	}
	return uriR{priority: priority, weight: weight, target: target}, nil
}

func unpackURI(u *wire.Unpacker, rdlen int) (URI, error) {
	if rdlen < 5 {
		return nil, fmt.Errorf("%w: URI rdlen=%d, want >=5", ErrInvalidRData, rdlen)
	}
	pr, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	w, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	t, err := u.Bytes(rdlen - 4)
	if err != nil {
		return nil, err
	}
	return uriR{priority: pr, weight: w, target: string(t)}, nil
}
