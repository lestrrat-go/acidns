package rdata

import (
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// DNAME is the DNAME (delegation name) rdata (RFC 6672 §2.1). The target
// MUST NOT be compressed on the wire (RFC 6672 §3.0).
type DNAME struct{ target wirebb.Name }

func (DNAME) Type() rrtype.Type       { return rrtype.DNAME }
func (DNAME) typedRData()             {}
func (d DNAME) Target() wirebb.Name   { return d.target }
func (d DNAME) Pack(p *wirebb.Packer) { p.NameUncompressed(d.target) }

// NewDNAME returns a DNAME rdata.
func NewDNAME(target wirebb.Name) DNAME { return DNAME{target: target} }

func unpackDNAME(u *wirebb.Unpacker, rdlen int) (DNAME, error) {
	var zero DNAME
	end := u.Off() + rdlen
	n, err := u.UncompressedNameInRange(end)
	if err != nil {
		return zero, err
	}
	return DNAME{target: n}, nil
}
