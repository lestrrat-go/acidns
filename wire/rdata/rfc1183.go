package rdata

import (
	"fmt"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// RP is the Responsible Person rdata (RFC 1183 §2.2).
type RP struct {
	mbox wirebb.Name
	txt  wirebb.Name
}

func (RP) Type() rrtype.Type       { return rrtype.RP }
func (RP) typedRData()             {}
func (r RP) Mbox() wirebb.Name     { return r.mbox }
func (r RP) TxtDName() wirebb.Name { return r.txt }
func (r RP) Pack(p *wirebb.Packer) {
	p.Name(r.mbox)
	p.Name(r.txt)
}

// NewRP returns an RP rdata.
func NewRP(mbox, txt wirebb.Name) RP { return RP{mbox: mbox, txt: txt} }

func unpackRP(u *wirebb.Unpacker) (RP, error) {
	var zero RP
	mbox, err := u.Name()
	if err != nil {
		return zero, err
	}
	txt, err := u.Name()
	if err != nil {
		return zero, err
	}
	return RP{mbox: mbox, txt: txt}, nil
}

// AFSDB is the AFS Data Base location rdata (RFC 1183 §1).
type AFSDB struct {
	subtype  uint16
	hostname wirebb.Name
}

func (AFSDB) Type() rrtype.Type       { return rrtype.AFSDB }
func (AFSDB) typedRData()             {}
func (a AFSDB) Subtype() uint16       { return a.subtype }
func (a AFSDB) Hostname() wirebb.Name { return a.hostname }
func (a AFSDB) Pack(p *wirebb.Packer) {
	p.Uint16(a.subtype)
	p.Name(a.hostname)
}

// NewAFSDB returns an AFSDB rdata.
func NewAFSDB(subtype uint16, hostname wirebb.Name) AFSDB {
	return AFSDB{subtype: subtype, hostname: hostname}
}

func unpackAFSDB(u *wirebb.Unpacker) (AFSDB, error) {
	var zero AFSDB
	st, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	n, err := u.Name()
	if err != nil {
		return zero, err
	}
	return AFSDB{subtype: st, hostname: n}, nil
}

// X25 is the X.25 PSDN address rdata (RFC 1183 §3.1).
type X25 struct{ addr string }

func (X25) Type() rrtype.Type       { return rrtype.X25 }
func (X25) typedRData()             {}
func (x X25) PSDNAddress() string   { return x.addr }
func (x X25) Pack(p *wirebb.Packer) { _ = p.CharString([]byte(x.addr)) }

// NewX25 returns an X25 rdata. The PSDN address must be ≤ 255 bytes.
func NewX25(addr string) (X25, error) {
	var zero X25
	if len(addr) > 255 {
		return zero, fmt.Errorf("%w: X25 address exceeds 255 bytes", ErrInvalidRData)
	}
	return X25{addr: addr}, nil
}

func unpackX25(u *wirebb.Unpacker) (X25, error) {
	var zero X25
	s, err := u.CharString()
	if err != nil {
		return zero, err
	}
	return X25{addr: string(s)}, nil
}

// ISDN is the ISDN address rdata (RFC 1183 §3.2).
type ISDN struct {
	addr   string
	sub    string
	hasSub bool
}

func (ISDN) Type() rrtype.Type    { return rrtype.ISDN }
func (ISDN) typedRData()          {}
func (i ISDN) Address() string    { return i.addr }
func (i ISDN) Subaddress() string { return i.sub }
func (i ISDN) Pack(p *wirebb.Packer) {
	_ = p.CharString([]byte(i.addr))
	if i.hasSub {
		_ = p.CharString([]byte(i.sub))
	}
}

// NewISDN returns an ISDN rdata. Subaddress is optional; pass empty string and
// hasSubaddress=false to omit it.
func NewISDN(addr, subaddress string, hasSubaddress bool) (ISDN, error) {
	var zero ISDN
	if len(addr) > 255 {
		return zero, fmt.Errorf("%w: ISDN address exceeds 255 bytes", ErrInvalidRData)
	}
	if len(subaddress) > 255 {
		return zero, fmt.Errorf("%w: ISDN subaddress exceeds 255 bytes", ErrInvalidRData)
	}
	return ISDN{addr: addr, sub: subaddress, hasSub: hasSubaddress}, nil
}

func unpackISDN(u *wirebb.Unpacker, rdlen int) (ISDN, error) {
	var zero ISDN
	end := u.Off() + rdlen
	addr, err := u.CharString()
	if err != nil {
		return zero, err
	}
	if u.Off() == end {
		return ISDN{addr: string(addr)}, nil
	}
	sub, err := u.CharString()
	if err != nil {
		return zero, err
	}
	return ISDN{addr: string(addr), sub: string(sub), hasSub: true}, nil
}

// RT is the Route Through rdata (RFC 1183 §3.3).
type RT struct {
	pref uint16
	host wirebb.Name
}

func (RT) Type() rrtype.Type               { return rrtype.RT }
func (RT) typedRData()                     {}
func (r RT) Preference() uint16            { return r.pref }
func (r RT) IntermediateHost() wirebb.Name { return r.host }
func (r RT) Pack(p *wirebb.Packer) {
	p.Uint16(r.pref)
	p.Name(r.host)
}

// NewRT returns an RT rdata.
func NewRT(pref uint16, host wirebb.Name) RT { return RT{pref: pref, host: host} }

func unpackRT(u *wirebb.Unpacker) (RT, error) {
	var zero RT
	pref, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	n, err := u.Name()
	if err != nil {
		return zero, err
	}
	return RT{pref: pref, host: n}, nil
}
