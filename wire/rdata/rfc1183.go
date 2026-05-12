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

// NewRP returns an RP rdata. Both names must be valid.
func NewRP(mbox, txt wirebb.Name) (RP, error) {
	if !mbox.IsValid() {
		return RP{}, fmt.Errorf("%w: RP mbox name is invalid", ErrInvalidRData)
	}
	if !txt.IsValid() {
		return RP{}, fmt.Errorf("%w: RP txt-dname is invalid", ErrInvalidRData)
	}
	return RP{mbox: mbox, txt: txt}, nil
}
func unpackRP(u *wirebb.Unpacker, rdlen int) (RP, error) {
	var zero RP
	end := u.Off() + rdlen
	mbox, err := u.NameInRange(end)
	if err != nil {
		return zero, err
	}
	txt, err := u.NameInRange(end)
	if err != nil {
		return zero, err
	}
	return RP{mbox: mbox, txt: txt}, nil
}

// AFSDB is the AFS Data Base location rdata (RFC 1183 §1). Per RFC 3597
// §4 the hostname MUST NOT be compressed on the wire.
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
	p.NameUncompressed(a.hostname)
}

// NewAFSDB returns an AFSDB rdata. The hostname must be a valid name.
func NewAFSDB(subtype uint16, hostname wirebb.Name) (AFSDB, error) {
	if !hostname.IsValid() {
		return AFSDB{}, fmt.Errorf("%w: AFSDB hostname is invalid", ErrInvalidRData)
	}
	return AFSDB{subtype: subtype, hostname: hostname}, nil
}
func unpackAFSDB(u *wirebb.Unpacker, rdlen int) (AFSDB, error) {
	var zero AFSDB
	end := u.Off() + rdlen
	st, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	n, err := u.UncompressedNameInRange(end)
	if err != nil {
		return zero, err
	}
	return AFSDB{subtype: st, hostname: n}, nil
}

// X25 is the X.25 PSDN address rdata (RFC 1183 §3.1).
type X25 struct{ addr string }

func (X25) Type() rrtype.Type     { return rrtype.X25 }
func (X25) typedRData()           {}
func (x X25) PSDNAddress() string { return x.addr }
func (x X25) Pack(p *wirebb.Packer) {
	// NewX25 rejects addr >255 bytes and the field is unexported,
	// so the CharString error is structurally unreachable here.
	_ = p.CharString([]byte(x.addr))
}

// NewX25 returns an X25 rdata. The PSDN address must be ≤ 255 bytes.
func NewX25(addr string) (X25, error) {
	var zero X25
	if len(addr) > 255 {
		return zero, fmt.Errorf("%w: X25 address exceeds 255 bytes", ErrInvalidRData)
	}
	return X25{addr: addr}, nil
}

func unpackX25(u *wirebb.Unpacker, rdlen int) (X25, error) {
	var zero X25
	end := u.Off() + rdlen
	s, err := u.CharStringInRange(end)
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
	// NewISDN rejects addr/sub >255 bytes and both fields are unexported,
	// so the CharString errors are structurally unreachable here.
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
	addr, err := u.CharStringInRange(end)
	if err != nil {
		return zero, err
	}
	if u.Off() == end {
		return ISDN{addr: string(addr)}, nil
	}
	sub, err := u.CharStringInRange(end)
	if err != nil {
		return zero, err
	}
	return ISDN{addr: string(addr), sub: string(sub), hasSub: true}, nil
}

// RT is the Route Through rdata (RFC 1183 §3.3). Per RFC 3597 §4 the
// intermediate-host name MUST NOT be compressed on the wire.
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
	p.NameUncompressed(r.host)
}

// NewRT returns an RT rdata. The intermediate-host must be a valid name.
func NewRT(pref uint16, host wirebb.Name) (RT, error) {
	if !host.IsValid() {
		return RT{}, fmt.Errorf("%w: RT intermediate-host name is invalid", ErrInvalidRData)
	}
	return RT{pref: pref, host: host}, nil
}
func unpackRT(u *wirebb.Unpacker, rdlen int) (RT, error) {
	var zero RT
	end := u.Off() + rdlen
	pref, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	n, err := u.UncompressedNameInRange(end)
	if err != nil {
		return zero, err
	}
	return RT{pref: pref, host: n}, nil
}
