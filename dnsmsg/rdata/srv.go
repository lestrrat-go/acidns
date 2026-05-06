package rdata

import (
	"github.com/lestrrat-go/acidns/dnsmsg/internal/wire"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
)

// SRV is the service-location rdata (RFC 2782).
type SRV interface {
	RData
	Priority() uint16
	Weight() uint16
	Port() uint16
	Target() dnsname.Name
}

type srv struct {
	priority uint16
	weight   uint16
	port     uint16
	target   dnsname.Name
}

func (srv) Type() rrtype.Type     { return rrtype.SRV }
func (s srv) Priority() uint16    { return s.priority }
func (s srv) Weight() uint16      { return s.weight }
func (s srv) Port() uint16        { return s.port }
func (s srv) Target() dnsname.Name { return s.target }
func (s srv) Pack(p *wire.Packer) {
	p.Uint16(s.priority)
	p.Uint16(s.weight)
	p.Uint16(s.port)
	// RFC 2782: target name MUST NOT be compressed.
	p.NameUncompressed(s.target)
}

// NewSRV returns an SRV rdata.
func NewSRV(priority, weight, port uint16, target dnsname.Name) SRV {
	return srv{priority: priority, weight: weight, port: port, target: target}
}

func unpackSRV(u *wire.Unpacker) (SRV, error) {
	priority, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	weight, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	port, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	target, err := u.Name()
	if err != nil {
		return nil, err
	}
	return srv{priority: priority, weight: weight, port: port, target: target}, nil
}
