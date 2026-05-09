package rdata

import (
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

// NewSRV returns an SRV rdata.
func NewSRV(priority, weight, port uint16, target wirebb.Name) SRV {
	return SRV{priority: priority, weight: weight, port: port, target: target}
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
	target, err := u.UncompressedNameInRange(end)
	if err != nil {
		return zero, err
	}
	return SRV{priority: priority, weight: weight, port: port, target: target}, nil
}
