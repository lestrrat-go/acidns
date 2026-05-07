package rdata

import (
	"fmt"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// RP is the Responsible Person rdata (RFC 1183 §2.2).
type RP interface {
	RData
	Mbox() wirebb.Name
	TxtDName() wirebb.Name
}

type rp struct {
	mbox wirebb.Name
	txt  wirebb.Name
}

func (rp) Type() rrtype.Type       { return rrtype.RP }
func (r rp) Mbox() wirebb.Name     { return r.mbox }
func (r rp) TxtDName() wirebb.Name { return r.txt }
func (r rp) Pack(p *wirebb.Packer) {
	p.Name(r.mbox)
	p.Name(r.txt)
}

// NewRP returns an RP rdata.
func NewRP(mbox, txt wirebb.Name) RP { return rp{mbox: mbox, txt: txt} }

func unpackRP(u *wirebb.Unpacker) (RP, error) {
	mbox, err := u.Name()
	if err != nil {
		return nil, err
	}
	txt, err := u.Name()
	if err != nil {
		return nil, err
	}
	return rp{mbox: mbox, txt: txt}, nil
}

// AFSDB is the AFS Data Base location rdata (RFC 1183 §1).
type AFSDB interface {
	RData
	Subtype() uint16
	Hostname() wirebb.Name
}

type afsdb struct {
	subtype  uint16
	hostname wirebb.Name
}

func (afsdb) Type() rrtype.Type       { return rrtype.AFSDB }
func (a afsdb) Subtype() uint16       { return a.subtype }
func (a afsdb) Hostname() wirebb.Name { return a.hostname }
func (a afsdb) Pack(p *wirebb.Packer) {
	p.Uint16(a.subtype)
	p.Name(a.hostname)
}

// NewAFSDB returns an AFSDB rdata.
func NewAFSDB(subtype uint16, hostname wirebb.Name) AFSDB {
	return afsdb{subtype: subtype, hostname: hostname}
}

func unpackAFSDB(u *wirebb.Unpacker) (AFSDB, error) {
	st, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	n, err := u.Name()
	if err != nil {
		return nil, err
	}
	return afsdb{subtype: st, hostname: n}, nil
}

// X25 is the X.25 PSDN address rdata (RFC 1183 §3.1).
type X25 interface {
	RData
	PSDNAddress() string
}

type x25 struct{ addr string }

func (x25) Type() rrtype.Type       { return rrtype.X25 }
func (x x25) PSDNAddress() string   { return x.addr }
func (x x25) Pack(p *wirebb.Packer) { _ = p.CharString([]byte(x.addr)) }

// NewX25 returns an X25 rdata. The PSDN address must be ≤ 255 bytes.
func NewX25(addr string) (X25, error) {
	if len(addr) > 255 {
		return nil, fmt.Errorf("%w: X25 address exceeds 255 bytes", ErrInvalidRData)
	}
	return x25{addr: addr}, nil
}

func unpackX25(u *wirebb.Unpacker) (X25, error) {
	s, err := u.CharString()
	if err != nil {
		return nil, err
	}
	return x25{addr: string(s)}, nil
}

// ISDN is the ISDN address rdata (RFC 1183 §3.2).
type ISDN interface {
	RData
	Address() string
	Subaddress() string
}

type isdn struct {
	addr   string
	sub    string
	hasSub bool
}

func (isdn) Type() rrtype.Type    { return rrtype.ISDN }
func (i isdn) Address() string    { return i.addr }
func (i isdn) Subaddress() string { return i.sub }
func (i isdn) Pack(p *wirebb.Packer) {
	_ = p.CharString([]byte(i.addr))
	if i.hasSub {
		_ = p.CharString([]byte(i.sub))
	}
}

// NewISDN returns an ISDN rdata. Subaddress is optional; pass empty string and
// hasSubaddress=false to omit it.
func NewISDN(addr, subaddress string, hasSubaddress bool) (ISDN, error) {
	if len(addr) > 255 {
		return nil, fmt.Errorf("%w: ISDN address exceeds 255 bytes", ErrInvalidRData)
	}
	if len(subaddress) > 255 {
		return nil, fmt.Errorf("%w: ISDN subaddress exceeds 255 bytes", ErrInvalidRData)
	}
	return isdn{addr: addr, sub: subaddress, hasSub: hasSubaddress}, nil
}

func unpackISDN(u *wirebb.Unpacker, rdlen int) (ISDN, error) {
	end := u.Off() + rdlen
	addr, err := u.CharString()
	if err != nil {
		return nil, err
	}
	if u.Off() == end {
		return isdn{addr: string(addr)}, nil
	}
	sub, err := u.CharString()
	if err != nil {
		return nil, err
	}
	return isdn{addr: string(addr), sub: string(sub), hasSub: true}, nil
}

// RT is the Route Through rdata (RFC 1183 §3.3).
type RT interface {
	RData
	Preference() uint16
	IntermediateHost() wirebb.Name
}

type rt struct {
	pref uint16
	host wirebb.Name
}

func (rt) Type() rrtype.Type               { return rrtype.RT }
func (r rt) Preference() uint16            { return r.pref }
func (r rt) IntermediateHost() wirebb.Name { return r.host }
func (r rt) Pack(p *wirebb.Packer) {
	p.Uint16(r.pref)
	p.Name(r.host)
}

// NewRT returns an RT rdata.
func NewRT(pref uint16, host wirebb.Name) RT { return rt{pref: pref, host: host} }

func unpackRT(u *wirebb.Unpacker) (RT, error) {
	pref, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	n, err := u.Name()
	if err != nil {
		return nil, err
	}
	return rt{pref: pref, host: n}, nil
}
