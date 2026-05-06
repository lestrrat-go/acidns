// Package dnsmsg defines the DNS wire-format message — header, question and
// resource record sections — together with a Builder for constructing
// outgoing messages and Marshal/Unmarshal for converting between Message
// values and on-the-wire bytes.
package dnsmsg

import (
	"fmt"

	"github.com/lestrrat-go/acidns/dnsmsg/internal/wire"
)

// Message is a DNS protocol message.
type Message interface {
	ID() uint16
	Flags() Flags
	Questions() []Question
	Answers() []Record
	Authorities() []Record
	Additionals() []Record
	EDNS() (EDNS, bool)
}

type message struct {
	id          uint16
	flags       Flags
	questions   []Question
	answers     []Record
	authorities []Record
	additionals []Record
	edns        EDNS
}

func (m *message) ID() uint16            { return m.id }
func (m *message) Flags() Flags          { return m.flags }
func (m *message) Questions() []Question { return m.questions }
func (m *message) Answers() []Record     { return m.answers }
func (m *message) Authorities() []Record { return m.authorities }
func (m *message) Additionals() []Record { return m.additionals }
func (m *message) EDNS() (EDNS, bool)    { return m.edns, m.edns != nil }

// Marshal encodes m to a single DNS wire-format datagram, using compression
// for repeated name suffixes.
func Marshal(m Message) ([]byte, error) {
	if len(m.Questions()) > 0xffff || len(m.Answers()) > 0xffff ||
		len(m.Authorities()) > 0xffff || len(m.Additionals()) > 0xffff {
		return nil, fmt.Errorf("%w: section count overflow", ErrInvalidMessage)
	}

	arcount := len(m.Additionals())
	if e, ok := m.EDNS(); ok && e != nil {
		arcount++
	}

	p := wire.NewPacker(make([]byte, 0, 64))
	p.Uint16(m.ID())
	p.Uint16(uint16(m.Flags()))
	p.Uint16(uint16(len(m.Questions())))
	p.Uint16(uint16(len(m.Answers())))
	p.Uint16(uint16(len(m.Authorities())))
	p.Uint16(uint16(arcount))

	for _, q := range m.Questions() {
		packQuestion(p, q)
	}
	for _, r := range m.Answers() {
		if err := packRecord(p, r); err != nil {
			return nil, err
		}
	}
	for _, r := range m.Authorities() {
		if err := packRecord(p, r); err != nil {
			return nil, err
		}
	}
	for _, r := range m.Additionals() {
		if err := packRecord(p, r); err != nil {
			return nil, err
		}
	}
	if e, ok := m.EDNS(); ok && e != nil {
		if err := packOPT(p, e); err != nil {
			return nil, err
		}
	}
	return p.Bytes(), nil
}

// Unmarshal decodes a wire-format DNS message.
func Unmarshal(buf []byte) (Message, error) {
	if len(buf) < 12 {
		return nil, fmt.Errorf("%w: header too short (%d bytes)", ErrInvalidMessage, len(buf))
	}
	u := wire.NewUnpacker(buf)
	id, _ := u.Uint16()
	flags, _ := u.Uint16()
	qdcount, _ := u.Uint16()
	ancount, _ := u.Uint16()
	nscount, _ := u.Uint16()
	arcount, _ := u.Uint16()

	m := &message{id: id, flags: Flags(flags)}

	m.questions = make([]Question, 0, qdcount)
	for range int(qdcount) {
		q, err := unpackQuestion(u)
		if err != nil {
			return nil, fmt.Errorf("%w: question: %w", ErrInvalidMessage, err)
		}
		m.questions = append(m.questions, q)
	}
	if err := unpackRRs(u, &m.answers, int(ancount), "answer"); err != nil {
		return nil, err
	}
	if err := unpackRRs(u, &m.authorities, int(nscount), "authority"); err != nil {
		return nil, err
	}
	if err := unpackAdditionals(u, m, int(arcount)); err != nil {
		return nil, err
	}
	return m, nil
}

func unpackRRs(u *wire.Unpacker, dst *[]Record, n int, section string) error {
	out := make([]Record, 0, n)
	for range n {
		r, err := unpackRecord(u)
		if err != nil {
			return fmt.Errorf("%w: %s: %w", ErrInvalidMessage, section, err)
		}
		out = append(out, r)
	}
	*dst = out
	return nil
}

// unpackAdditionals splits the additional section into regular records and
// the OPT pseudo-RR (if any).
func unpackAdditionals(u *wire.Unpacker, m *message, n int) error {
	out := make([]Record, 0, n)
	for range n {
		// Peek at the type without committing the unpacker.
		save := u.Off()
		if _, err := u.Name(); err != nil {
			return fmt.Errorf("%w: additional: %w", ErrInvalidMessage, err)
		}
		t, err := u.Uint16()
		if err != nil {
			return fmt.Errorf("%w: additional: %w", ErrInvalidMessage, err)
		}
		u.SetOff(save)

		if t == optTypeWire {
			if m.edns != nil {
				return fmt.Errorf("%w: multiple OPT pseudo-RRs", ErrInvalidMessage)
			}
			e, err := unpackOPT(u)
			if err != nil {
				return fmt.Errorf("%w: additional: %w", ErrInvalidMessage, err)
			}
			m.edns = e
			continue
		}
		r, err := unpackRecord(u)
		if err != nil {
			return fmt.Errorf("%w: additional: %w", ErrInvalidMessage, err)
		}
		out = append(out, r)
	}
	m.additionals = out
	return nil
}
