package wire

import (
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// Question is a DNS question section entry: a (name, type, class) triple.
type Question interface {
	Name() wirebb.Name
	Type() rrtype.Type
	Class() rrtype.Class
}

type question struct {
	name  wirebb.Name
	typ   rrtype.Type
	class rrtype.Class
	// rawName holds the original uncompressed wire bytes of the qname
	// as they arrived on the wire, including the original case. It is
	// populated by unpackQuestion and used by packQuestion so a server
	// can echo the question section back to the querier byte-exact —
	// required for RFC 5452 §9.3 0x20 verification on the client.
	// Empty for questions constructed via NewQuestion / NewQuestionClass,
	// in which case the canonical lowercase form is packed instead.
	rawName []byte
}

func (q question) Name() wirebb.Name   { return q.name }
func (q question) Type() rrtype.Type   { return q.typ }
func (q question) Class() rrtype.Class { return q.class }

// NewQuestion returns a Question with class IN.
func NewQuestion(name wirebb.Name, t rrtype.Type) Question {
	return question{name: name, typ: t, class: rrtype.ClassIN}
}

// NewQuestionClass returns a Question with the given class.
func NewQuestionClass(name wirebb.Name, t rrtype.Type, c rrtype.Class) Question {
	return question{name: name, typ: t, class: c}
}

func packQuestion(p *wirebb.Packer, q Question) {
	if qq, ok := q.(question); ok && len(qq.rawName) > 0 {
		p.Raw(qq.rawName)
	} else {
		p.NameUncompressed(q.Name())
	}
	p.Uint16(uint16(q.Type()))
	p.Uint16(uint16(q.Class()))
}

func unpackQuestion(u *wirebb.Unpacker) (Question, error) {
	msg := u.Msg()
	start := u.Off()
	n, err := u.Name()
	if err != nil {
		return nil, err
	}
	// Capture the original wire bytes of the qname so a server can
	// echo them back verbatim. RFC 1035 §4.1.2 forbids compression
	// pointers in the question section, but defensively skip raw
	// preservation if any pointer byte is present so we never emit a
	// pointer into a wire offset that won't exist in the response.
	end := u.Off()
	var raw []byte
	if start >= 0 && end > start && end <= len(msg) {
		raw = msg[start:end]
		hasPointer := false
		off := 0
		for off < len(raw) {
			b := raw[off]
			if b&0xc0 == 0xc0 {
				hasPointer = true
				break
			}
			if b == 0 {
				break
			}
			off += 1 + int(b)
		}
		if hasPointer {
			raw = nil
		} else {
			raw = append([]byte(nil), raw...)
		}
	}
	t, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	c, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	return question{name: n, typ: rrtype.Type(t), class: rrtype.Class(c), rawName: raw}, nil
}
