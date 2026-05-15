package rdata

import (
	"fmt"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// SRV is the service-location rdata (RFC 2782).
type SRV struct {
	priority uint16
	weight   uint16
	port     uint16
	target   wirebb.Name
}

func (SRV) Type() rrtype.Type     { return rrtype.SRV }
func (SRV) typedRData()           {}
func (s SRV) Priority() uint16    { return s.priority }
func (s SRV) Weight() uint16      { return s.weight }
func (s SRV) Port() uint16        { return s.port }
func (s SRV) Target() wirebb.Name { return s.target }
func (s SRV) Pack(p *wirebb.Packer) {
	p.Uint16(s.priority)
	p.Uint16(s.weight)
	p.Uint16(s.port)
	// RFC 2782: target name MUST NOT be compressed.
	p.NameUncompressed(s.target)
}

// NewSRV returns an SRV rdata. Returns [ErrInvalidRData] when target
// is the zero name. RFC 2782 specifies a target of "." (root) as the
// "service decidedly not available" sentinel — that is a non-zero
// valid root name, distinct from the zero/uninitialised name this
// check rejects.
func NewSRV(priority, weight, port uint16, target wirebb.Name) (SRV, error) {
	if !target.IsValid() {
		return SRV{}, fmt.Errorf("%w: SRV target name is invalid", ErrInvalidRData)
	}
	return SRV{priority: priority, weight: weight, port: port, target: target}, nil
}
func unpackSRV(u *wirebb.Unpacker, rdlen int) (SRV, error) {
	var zero SRV
	end := u.Off() + rdlen
	priority, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	weight, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	port, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	target, err := u.UncompressedName(end - u.Off())
	if err != nil {
		return zero, err
	}
	return SRV{priority: priority, weight: weight, port: port, target: target}, nil
}
