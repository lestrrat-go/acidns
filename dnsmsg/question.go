package dnsmsg

import (
	"github.com/lestrrat-go/acidns/dnsmsg/internal/wire"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
)

// Question is a DNS question section entry: a (name, type, class) triple.
type Question interface {
	Name() dnsname.Name
	Type() rrtype.Type
	Class() rrtype.Class
}

type question struct {
	name  dnsname.Name
	typ   rrtype.Type
	class rrtype.Class
}

func (q question) Name() dnsname.Name  { return q.name }
func (q question) Type() rrtype.Type   { return q.typ }
func (q question) Class() rrtype.Class { return q.class }

// NewQuestion returns a Question with class IN.
func NewQuestion(name dnsname.Name, t rrtype.Type) Question {
	return question{name: name, typ: t, class: rrtype.ClassIN}
}

// NewQuestionClass returns a Question with the given class.
func NewQuestionClass(name dnsname.Name, t rrtype.Type, c rrtype.Class) Question {
	return question{name: name, typ: t, class: c}
}

func packQuestion(p *wire.Packer, q Question) {
	p.Name(q.Name())
	p.Uint16(uint16(q.Type()))
	p.Uint16(uint16(q.Class()))
}

func unpackQuestion(u *wire.Unpacker) (Question, error) {
	n, err := u.Name()
	if err != nil {
		return nil, err
	}
	t, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	c, err := u.Uint16()
	if err != nil {
		return nil, err
	}
	return question{name: n, typ: rrtype.Type(t), class: rrtype.Class(c)}, nil
}
