// Package wire is the low-level DNS wire codec shared by dnsmsg and rdata.
// It is internal to dnsmsg and not part of the public API surface.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/lestrrat-go/acidns/dnsname"
)

// ErrTruncated is returned when an unpacker runs out of input.
var ErrTruncated = errors.New("wire: truncated")

// Packer accumulates a DNS message wire encoding while tracking previously
// emitted name suffixes so subsequent names can be replaced with compression
// pointers per RFC 1035 §4.1.4.
type Packer struct {
	buf  []byte
	comp map[string]int
}

// NewPacker returns a Packer that writes into buf (which may be nil).
func NewPacker(buf []byte) *Packer {
	return &Packer{buf: buf, comp: make(map[string]int)}
}

func (p *Packer) Bytes() []byte { return p.buf }
func (p *Packer) Len() int      { return len(p.buf) }

func (p *Packer) Uint8(v uint8)   { p.buf = append(p.buf, v) }
func (p *Packer) Uint16(v uint16) { p.buf = binary.BigEndian.AppendUint16(p.buf, v) }
func (p *Packer) Uint32(v uint32) { p.buf = binary.BigEndian.AppendUint32(p.buf, v) }

// Raw appends raw bytes verbatim.
func (p *Packer) Raw(b []byte) { p.buf = append(p.buf, b...) }

// CharString appends a length-prefixed character string. Returns an error if
// s exceeds 255 bytes.
func (p *Packer) CharString(s []byte) error {
	if len(s) > 255 {
		return fmt.Errorf("wire: character string exceeds 255 bytes")
	}
	p.buf = append(p.buf, byte(len(s)))
	p.buf = append(p.buf, s...)
	return nil
}

// Name appends a domain name with compression. Compression points record
// each suffix (label sequence) at its first appearance; subsequent uses of
// the same suffix become 2-byte pointers into the prior offset.
func (p *Packer) Name(n dnsname.Name) {
	wire := nameWire(n)
	off := 0
	for off < len(wire) {
		l := int(wire[off])
		if l == 0 {
			p.buf = append(p.buf, 0)
			return
		}
		suffix := wire[off:]
		if ptr, ok := p.comp[suffix]; ok && ptr < 1<<14 && len(p.buf) < 1<<14 {
			p.buf = append(p.buf, 0xc0|byte(ptr>>8), byte(ptr))
			return
		}
		if len(p.buf) < 1<<14 {
			p.comp[suffix] = len(p.buf)
		}
		p.buf = append(p.buf, byte(l))
		p.buf = append(p.buf, wire[off+1:off+1+l]...)
		off += 1 + l
	}
}

// NameUncompressed appends n without consulting the compression table.
// Useful for names within rdata of types where compression is forbidden.
func (p *Packer) NameUncompressed(n dnsname.Name) {
	p.buf = n.AppendWire(p.buf)
}

func nameWire(n dnsname.Name) string {
	if !n.IsValid() {
		return "\x00"
	}
	// AppendWire round-trips to the canonical wire bytes
	return string(n.AppendWire(nil))
}

// Unpacker reads DNS wire data with bounds checking and pointer-following
// name decoding.
type Unpacker struct {
	msg []byte
	off int
}

func NewUnpacker(msg []byte) *Unpacker { return &Unpacker{msg: msg} }

func (u *Unpacker) Off() int       { return u.off }
func (u *Unpacker) Remaining() int { return len(u.msg) - u.off }
func (u *Unpacker) SetOff(o int)   { u.off = o }
func (u *Unpacker) Msg() []byte    { return u.msg }

func (u *Unpacker) Uint8() (uint8, error) {
	if u.off+1 > len(u.msg) {
		return 0, fmt.Errorf("%w: uint8 at off %d", ErrTruncated, u.off)
	}
	v := u.msg[u.off]
	u.off++
	return v, nil
}

func (u *Unpacker) Uint16() (uint16, error) {
	if u.off+2 > len(u.msg) {
		return 0, fmt.Errorf("%w: uint16 at off %d", ErrTruncated, u.off)
	}
	v := binary.BigEndian.Uint16(u.msg[u.off:])
	u.off += 2
	return v, nil
}

func (u *Unpacker) Uint32() (uint32, error) {
	if u.off+4 > len(u.msg) {
		return 0, fmt.Errorf("%w: uint32 at off %d", ErrTruncated, u.off)
	}
	v := binary.BigEndian.Uint32(u.msg[u.off:])
	u.off += 4
	return v, nil
}

// Bytes returns a slice of n bytes from the current offset, advancing it.
// The slice aliases the underlying message; copy if it must outlive it.
func (u *Unpacker) Bytes(n int) ([]byte, error) {
	if n < 0 || u.off+n > len(u.msg) {
		return nil, fmt.Errorf("%w: %d bytes at off %d", ErrTruncated, n, u.off)
	}
	b := u.msg[u.off : u.off+n]
	u.off += n
	return b, nil
}

// CharString reads a length-prefixed character string.
func (u *Unpacker) CharString() ([]byte, error) {
	l, err := u.Uint8()
	if err != nil {
		return nil, err
	}
	return u.Bytes(int(l))
}

// Name decodes a domain name from the current offset, following any
// compression pointers, and advances the offset past the on-the-wire
// encoding (not past pointer targets).
func (u *Unpacker) Name() (dnsname.Name, error) {
	n, next, err := dnsname.DecodeWire(u.msg, u.off)
	if err != nil {
		return dnsname.Name{}, err
	}
	u.off = next
	return n, nil
}
