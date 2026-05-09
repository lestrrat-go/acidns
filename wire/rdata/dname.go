package rdata

import (
	"fmt"

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

// NewDNAME returns a DNAME rdata. The target must be a valid name.
func NewDNAME(target wirebb.Name) (DNAME, error) {
	if !target.IsValid() {
		return DNAME{}, fmt.Errorf("%w: DNAME target name is invalid", ErrInvalidRData)
	}
	return DNAME{target: target}, nil
}

// MustNewDNAME is the panic-on-error variant of [NewDNAME].
func MustNewDNAME(target wirebb.Name) DNAME {
	d, err := NewDNAME(target)
	if err != nil {
		panic(err)
	}
	return d
}

func unpackDNAME(u *wirebb.Unpacker, rdlen int) (DNAME, error) {
	var zero DNAME
	end := u.Off() + rdlen
	// Bound the name decode to the rdata window so a malformed peer
	// cannot make the decoder walk into the next record before the
	// outer off==end guard fires.
	n, err := u.UncompressedNameInRange(end)
	if err != nil {
		return zero, err
	}
	return DNAME{target: n}, nil
}
