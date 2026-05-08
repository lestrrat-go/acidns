package rdata

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// SvcParamKey is a 16-bit key identifying a SvcParam (RFC 9460 §14.3).
type SvcParamKey uint16

const (
	SvcParamMandatory     SvcParamKey = 0
	SvcParamALPN          SvcParamKey = 1
	SvcParamNoDefaultALPN SvcParamKey = 2
	SvcParamPort          SvcParamKey = 3
	SvcParamIPv4Hint      SvcParamKey = 4
	SvcParamECH           SvcParamKey = 5
	SvcParamIPv6Hint      SvcParamKey = 6
	SvcParamDOHPath       SvcParamKey = 7
)

// SVCBParam is a single (key, value) pair in the SvcParams of an SVCB or
// HTTPS record. The value is the raw on-the-wire encoding; helpers on
// SVCB / HTTPS decode the well-known forms.
type SVCBParam struct {
	key  SvcParamKey
	data []byte
}

func (p SVCBParam) Key() SvcParamKey { return p.key }
func (p SVCBParam) Value() []byte    { return p.data }

// NewSVCBParam returns a generic SvcParam.
func NewSVCBParam(key SvcParamKey, data []byte) SVCBParam {
	cp := make([]byte, len(data))
	copy(cp, data)
	return SVCBParam{key: key, data: cp}
}

// svcbBody carries the fields shared by SVCB and HTTPS records, which have
// identical wire formats and differ only in their RR type code. SVCB and
// HTTPS embed svcbBody to inherit accessors; each provides its own
// Type() returning the appropriate rrtype constant.
type svcbBody struct {
	priority uint16
	target   wirebb.Name
	params   []SVCBParam
}

func (s svcbBody) Priority() uint16    { return s.priority }
func (s svcbBody) Target() wirebb.Name { return s.target }
func (s svcbBody) Params() []SVCBParam { return s.params }

func (s svcbBody) packBody(p *wirebb.Packer) {
	p.Uint16(s.priority)
	p.NameUncompressed(s.target)
	for _, sp := range s.params {
		p.Uint16(uint16(sp.Key()))
		p.Uint16(uint16(len(sp.Value())))
		p.Raw(sp.Value())
	}
}

func (s svcbBody) ALPN() []string {
	for _, p := range s.params {
		if p.Key() != SvcParamALPN {
			continue
		}
		return decodeALPN(p.Value())
	}
	return nil
}

func (s svcbBody) Port() (uint16, bool) {
	for _, p := range s.params {
		if p.Key() == SvcParamPort && len(p.Value()) == 2 {
			return binary.BigEndian.Uint16(p.Value()), true
		}
	}
	return 0, false
}

func (s svcbBody) IPv4Hints() []netip.Addr {
	return decodeAddrHint(s.params, SvcParamIPv4Hint, 4)
}

func (s svcbBody) IPv6Hints() []netip.Addr {
	return decodeAddrHint(s.params, SvcParamIPv6Hint, 16)
}

// DOHPath returns the DoH URI template (RFC 9461 §5) when the
// SvcParamDOHPath key is present.
func (s svcbBody) DOHPath() (string, bool) {
	for _, p := range s.params {
		if p.Key() == SvcParamDOHPath {
			return string(p.Value()), true
		}
	}
	return "", false
}

// SVCB is the SVCB rdata (RFC 9460).
type SVCB struct{ svcbBody }

func (SVCB) Type() rrtype.Type       { return rrtype.SVCB }
func (SVCB) typedRData()             {}
func (s SVCB) Pack(p *wirebb.Packer) { s.packBody(p) }

// HTTPS is the HTTPS rdata (RFC 9460). Wire format identical to SVCB; only
// the RR type code differs.
type HTTPS struct{ svcbBody }

func (HTTPS) Type() rrtype.Type       { return rrtype.HTTPS }
func (HTTPS) typedRData()             {}
func (s HTTPS) Pack(p *wirebb.Packer) { s.packBody(p) }

// NewSvcParamALPN builds an ALPN SvcParam (RFC 9460 §7.1).
func NewSvcParamALPN(alpns ...string) (SVCBParam, error) {
	var zero SVCBParam
	var buf []byte
	for i, a := range alpns {
		if len(a) == 0 || len(a) > 255 {
			return zero, fmt.Errorf("%w: ALPN[%d] length %d not in [1,255]", ErrInvalidRData, i, len(a))
		}
		buf = append(buf, byte(len(a)))
		buf = append(buf, a...)
	}
	return SVCBParam{key: SvcParamALPN, data: buf}, nil
}

// NewSvcParamPort builds a Port SvcParam (RFC 9460 §7.2).
func NewSvcParamPort(port uint16) SVCBParam {
	return SVCBParam{key: SvcParamPort, data: []byte{byte(port >> 8), byte(port)}}
}

// NewSvcParamIPv4Hint builds an ipv4hint SvcParam (RFC 9460 §7.3).
func NewSvcParamIPv4Hint(addrs ...netip.Addr) (SVCBParam, error) {
	var zero SVCBParam
	buf := make([]byte, 0, 4*len(addrs))
	for i, a := range addrs {
		if !a.Is4() {
			return zero, fmt.Errorf("%w: ipv4hint[%d] is not IPv4", ErrInvalidRData, i)
		}
		b := a.As4()
		buf = append(buf, b[:]...)
	}
	return SVCBParam{key: SvcParamIPv4Hint, data: buf}, nil
}

// NewSvcParamIPv6Hint builds an ipv6hint SvcParam (RFC 9460 §7.4).
func NewSvcParamIPv6Hint(addrs ...netip.Addr) (SVCBParam, error) {
	var zero SVCBParam
	buf := make([]byte, 0, 16*len(addrs))
	for i, a := range addrs {
		if !a.Is6() {
			return zero, fmt.Errorf("%w: ipv6hint[%d] is not IPv6", ErrInvalidRData, i)
		}
		b := a.As16()
		buf = append(buf, b[:]...)
	}
	return SVCBParam{key: SvcParamIPv6Hint, data: buf}, nil
}

// NewSvcParamDOHPath builds a dohpath SvcParam (RFC 9461 §5). The path is
// a URI template per RFC 6570.
func NewSvcParamDOHPath(template string) SVCBParam {
	return SVCBParam{key: SvcParamDOHPath, data: []byte(template)}
}

func decodeAddrHint(params []SVCBParam, key SvcParamKey, sz int) []netip.Addr {
	for _, p := range params {
		if p.Key() != key {
			continue
		}
		v := p.Value()
		if len(v)%sz != 0 {
			return nil
		}
		out := make([]netip.Addr, 0, len(v)/sz)
		for off := 0; off < len(v); off += sz {
			switch sz {
			case 4:
				out = append(out, netip.AddrFrom4([4]byte(v[off:off+4])))
			case 16:
				out = append(out, netip.AddrFrom16([16]byte(v[off:off+16])))
			}
		}
		return out
	}
	return nil
}

func decodeALPN(buf []byte) []string {
	var out []string
	for off := 0; off < len(buf); {
		l := int(buf[off])
		off++
		if off+l > len(buf) {
			return nil
		}
		out = append(out, string(buf[off:off+l]))
		off += l
	}
	return out
}

// NewSVCB returns an SVCB rdata.
func NewSVCB(priority uint16, target wirebb.Name, params ...SVCBParam) SVCB {
	return SVCB{svcbBody{
		priority: priority,
		target:   target,
		params:   append([]SVCBParam(nil), params...),
	}}
}

// NewHTTPS returns an HTTPS rdata. Wire-format identical to SVCB; only the
// RR type code differs.
func NewHTTPS(priority uint16, target wirebb.Name, params ...SVCBParam) HTTPS {
	return HTTPS{svcbBody{
		priority: priority,
		target:   target,
		params:   append([]SVCBParam(nil), params...),
	}}
}

func unpackSVCB(t rrtype.Type, u *wirebb.Unpacker, rdlen int) (RData, error) {
	body, err := unpackSvcbBody(u, rdlen)
	if err != nil {
		return nil, err
	}
	switch t {
	case rrtype.SVCB:
		return SVCB{body}, nil
	case rrtype.HTTPS:
		return HTTPS{body}, nil
	default:
		return nil, fmt.Errorf("%w: unexpected SVCB-family type %s", ErrInvalidRData, t)
	}
}

func unpackSvcbBody(u *wirebb.Unpacker, rdlen int) (svcbBody, error) {
	var zero svcbBody
	end := u.Off() + rdlen
	prio, err := u.Uint16()
	if err != nil {
		return zero, err
	}
	target, err := u.UncompressedNameInRange(end)
	if err != nil {
		return zero, err
	}
	var params []SVCBParam
	// RFC 9460 §2.2 requires SvcParams to appear in strictly-increasing
	// key order with no duplicates. Permitting arbitrary order would
	// make first-match accessors (Port(), ALPN(), ...) silently shadow
	// duplicate keys and disagree with peers that enforce the rule.
	lastKey := -1
	for u.Off() < end {
		key, err := u.Uint16()
		if err != nil {
			return zero, err
		}
		if int(key) <= lastKey {
			return zero, fmt.Errorf("%w: SVCB params out of order or duplicate (key %d after %d)", ErrInvalidRData, key, lastKey)
		}
		lastKey = int(key)
		l, err := u.Uint16()
		if err != nil {
			return zero, err
		}
		if u.Off()+int(l) > end {
			return zero, fmt.Errorf("%w: SVCB param length out of range", ErrInvalidRData)
		}
		v, err := u.Bytes(int(l))
		if err != nil {
			return zero, err
		}
		cp := make([]byte, len(v))
		copy(cp, v)
		params = append(params, SVCBParam{key: SvcParamKey(key), data: cp})
	}
	return svcbBody{priority: prio, target: target, params: params}, nil
}
