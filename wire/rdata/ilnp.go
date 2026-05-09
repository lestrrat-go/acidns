package rdata

import (
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// NID is the ILNP Node Identifier rdata (RFC 6742 §2.1).
type NID struct {
	pref uint16
	id   uint64
}

func (NID) Type() rrtype.Type    { return rrtype.NID }
func (NID) typedRData()          {}
func (n NID) Preference() uint16 { return n.pref }
func (n NID) NodeID() uint64     { return n.id }
func (n NID) Pack(p *wirebb.Packer) {
	p.Uint16(n.pref)
	p.Uint32(uint32(n.id >> 32))
	p.Uint32(uint32(n.id))
}

// NewNID returns an NID rdata.
func NewNID(pref uint16, nodeID uint64) NID { return NID{pref: pref, id: nodeID} }

func unpackNID(u *wirebb.Unpacker) (NID, error) {
	var zero NID
	pref, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	hi, err := u.Uint32()
	if err != nil {
		return zero, err
	}
	lo, err := u.Uint32()
	if err != nil {
		return zero, err
	}
	return NID{pref: pref, id: uint64(hi)<<32 | uint64(lo)}, nil
}

// L32 is the ILNP 32-bit Locator rdata (RFC 6742 §2.2).
type L32 struct {
	pref uint16
	loc  uint32
}

func (L32) Type() rrtype.Type    { return rrtype.L32 }
func (L32) typedRData()          {}
func (l L32) Preference() uint16 { return l.pref }
func (l L32) Locator() uint32    { return l.loc }
func (l L32) Pack(p *wirebb.Packer) {
	p.Uint16(l.pref)
	p.Uint32(l.loc)
}

// NewL32 returns an L32 rdata.
func NewL32(pref uint16, locator uint32) L32 { return L32{pref: pref, loc: locator} }

func unpackL32(u *wirebb.Unpacker) (L32, error) {
	var zero L32
	pref, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	loc, err := u.Uint32()
	if err != nil {
		return zero, err
	}
	return L32{pref: pref, loc: loc}, nil
}

// L64 is the ILNP 64-bit Locator rdata (RFC 6742 §2.3).
type L64 struct {
	pref uint16
	loc  uint64
}

func (L64) Type() rrtype.Type    { return rrtype.L64 }
func (L64) typedRData()          {}
func (l L64) Preference() uint16 { return l.pref }
func (l L64) Locator() uint64    { return l.loc }
func (l L64) Pack(p *wirebb.Packer) {
	p.Uint16(l.pref)
	p.Uint32(uint32(l.loc >> 32))
	p.Uint32(uint32(l.loc))
}

// NewL64 returns an L64 rdata.
func NewL64(pref uint16, locator uint64) L64 { return L64{pref: pref, loc: locator} }

func unpackL64(u *wirebb.Unpacker) (L64, error) {
	var zero L64
	pref, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	hi, err := u.Uint32()
	if err != nil {
		return zero, err
	}
	lo, err := u.Uint32()
	if err != nil {
		return zero, err
	}
	return L64{pref: pref, loc: uint64(hi)<<32 | uint64(lo)}, nil
}

// LP is the ILNP locator-pointer rdata (RFC 6742 §2.4).
type LP struct {
	pref uint16
	fqdn wirebb.Name
}

func (LP) Type() rrtype.Type    { return rrtype.LP }
func (LP) typedRData()          {}
func (l LP) Preference() uint16 { return l.pref }
func (l LP) FQDN() wirebb.Name  { return l.fqdn }
func (l LP) Pack(p *wirebb.Packer) {
	p.Uint16(l.pref)
	// RFC 6742 §2.4: name is uncompressed.
	p.NameUncompressed(l.fqdn)
}

// NewLP returns an LP rdata.
func NewLP(pref uint16, fqdn wirebb.Name) LP { return LP{pref: pref, fqdn: fqdn} }

func unpackLP(u *wirebb.Unpacker, rdlen int) (LP, error) {
	var zero LP
	end := u.Off() + rdlen
	pref, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	n, err := u.UncompressedNameInRange(end)
	if err != nil {
		return zero, err
	}
	return LP{pref: pref, fqdn: n}, nil
}
