package rdata

import (
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// NID is the ILNP Node Identifier rdata (RFC 6742 §2.1).
type NID interface {
	RData
	Preference() uint16
	NodeID() uint64
}

type nid struct {
	pref uint16
	id   uint64
}

func (nid) Type() rrtype.Type    { return rrtype.NID }
func (n nid) Preference() uint16 { return n.pref }
func (n nid) NodeID() uint64     { return n.id }
func (n nid) Pack(p *wirebb.Packer) {
	p.Uint16(n.pref)
	p.Uint32(uint32(n.id >> 32))
	p.Uint32(uint32(n.id))
}

// NewNID returns an NID rdata.
func NewNID(pref uint16, nodeID uint64) NID { return nid{pref: pref, id: nodeID} }

func unpackNID(u *wirebb.Unpacker) (NID, error) {
	pref, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	hi, err := u.Uint32()
	if err != nil {
		return nil, err
	}
	lo, err := u.Uint32()
	if err != nil {
		return nil, err
	}
	return nid{pref: pref, id: uint64(hi)<<32 | uint64(lo)}, nil
}

// L32 is the ILNP 32-bit Locator rdata (RFC 6742 §2.2).
type L32 interface {
	RData
	Preference() uint16
	Locator() uint32
}

type l32 struct {
	pref uint16
	loc  uint32
}

func (l32) Type() rrtype.Type    { return rrtype.L32 }
func (l l32) Preference() uint16 { return l.pref }
func (l l32) Locator() uint32    { return l.loc }
func (l l32) Pack(p *wirebb.Packer) {
	p.Uint16(l.pref)
	p.Uint32(l.loc)
}

// NewL32 returns an L32 rdata.
func NewL32(pref uint16, locator uint32) L32 { return l32{pref: pref, loc: locator} }

func unpackL32(u *wirebb.Unpacker) (L32, error) {
	pref, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	loc, err := u.Uint32()
	if err != nil {
		return nil, err
	}
	return l32{pref: pref, loc: loc}, nil
}

// L64 is the ILNP 64-bit Locator rdata (RFC 6742 §2.3).
type L64 interface {
	RData
	Preference() uint16
	Locator() uint64
}

type l64 struct {
	pref uint16
	loc  uint64
}

func (l64) Type() rrtype.Type    { return rrtype.L64 }
func (l l64) Preference() uint16 { return l.pref }
func (l l64) Locator() uint64    { return l.loc }
func (l l64) Pack(p *wirebb.Packer) {
	p.Uint16(l.pref)
	p.Uint32(uint32(l.loc >> 32))
	p.Uint32(uint32(l.loc))
}

// NewL64 returns an L64 rdata.
func NewL64(pref uint16, locator uint64) L64 { return l64{pref: pref, loc: locator} }

func unpackL64(u *wirebb.Unpacker) (L64, error) {
	pref, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	hi, err := u.Uint32()
	if err != nil {
		return nil, err
	}
	lo, err := u.Uint32()
	if err != nil {
		return nil, err
	}
	return l64{pref: pref, loc: uint64(hi)<<32 | uint64(lo)}, nil
}

// LP is the ILNP locator-pointer rdata (RFC 6742 §2.4).
type LP interface {
	RData
	Preference() uint16
	FQDN() wirebb.Name
}

type lp struct {
	pref uint16
	fqdn wirebb.Name
}

func (lp) Type() rrtype.Type    { return rrtype.LP }
func (l lp) Preference() uint16 { return l.pref }
func (l lp) FQDN() wirebb.Name  { return l.fqdn }
func (l lp) Pack(p *wirebb.Packer) {
	p.Uint16(l.pref)
	// RFC 6742 §2.4: name is uncompressed.
	p.NameUncompressed(l.fqdn)
}

// NewLP returns an LP rdata.
func NewLP(pref uint16, fqdn wirebb.Name) LP { return lp{pref: pref, fqdn: fqdn} }

func unpackLP(u *wirebb.Unpacker) (LP, error) {
	pref, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	n, err := u.Name()
	if err != nil {
		return nil, err
	}
	return lp{pref: pref, fqdn: n}, nil
}
