package wire

import (
	"fmt"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// Question is a DNS question section entry: a (name, type, class)
// triple. Value type — copy-friendly, immutable, returned by value
// from [Message.Questions]. Construct via [NewQuestion] /
// [NewQuestionClass] so callers do not depend on field layout.
type Question struct {
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

// Name returns the queried name.
func (q Question) Name() wirebb.Name { return q.name }

// Type returns the queried RR type.
func (q Question) Type() rrtype.Type { return q.typ }

// Class returns the queried class.
func (q Question) Class() rrtype.Class { return q.class }

// NewQuestion returns a Question with class IN.
func NewQuestion(name wirebb.Name, t rrtype.Type) Question {
	return Question{name: name, typ: t, class: rrtype.ClassIN}
}

// NewQuestionClass returns a Question with the given class.
func NewQuestionClass(name wirebb.Name, t rrtype.Type, c rrtype.Class) Question {
	return Question{name: name, typ: t, class: c}
}

func packQuestion(p *wirebb.Packer, q Question) {
	if len(q.rawName) > 0 {
		p.Raw(q.rawName)
	} else {
		p.NameUncompressed(q.name)
	}
	p.Uint16(uint16(q.typ))
	p.Uint16(uint16(q.class))
}

func unpackQuestion(u *wirebb.Unpacker) (Question, error) {
	msg := u.Msg()
	start := u.Off()
	n, err := u.Name()
	if err != nil {
		return Question{}, err
	}
	// Capture the original wire bytes of the qname so a server can
	// echo them back verbatim — required for RFC 5452 §9.3 0x20
	// verification on the client. RFC 1035 §4.1.2 silently allows
	// compression in any name field, but the question section is the
	// only context where the client side relies on byte-for-byte echo,
	// and a compression pointer there can be used by a man-on-the-side
	// to point the parser at attacker-controlled bytes elsewhere in
	// the message and bypass case-mismatch verification. Reject
	// compressed qnames outright.
	end := u.Off()
	var raw []byte
	if start >= 0 && end > start && end <= len(msg) {
		raw = msg[start:end]
		off := 0
		for off < len(raw) {
			b := raw[off]
			if b&0xc0 == 0xc0 {
				return Question{}, fmt.Errorf("%w: compression pointer in question section", ErrInvalidMessage)
			}
			if b == 0 {
				break
			}
			off += 1 + int(b)
		}
		raw = append([]byte(nil), raw...)
	}
	t, err := u.Uint16()
	if err != nil {
		return Question{}, err
	}
	c, err := u.Uint16()
	if err != nil {
		return Question{}, err
	}
	return Question{name: n, typ: rrtype.Type(t), class: rrtype.Class(c), rawName: raw}, nil
}
