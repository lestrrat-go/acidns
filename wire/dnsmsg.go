package wire

import (
	"fmt"
	"slices"

	"github.com/lestrrat-go/acidns/wire/wirebb"
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

// WithID returns a copy of m whose transaction ID has been replaced
// with id. Resolvers retry-loops use this to mint a fresh ID per
// outbound attempt: RFC 5452 §10 expects each fired query to draw an
// independent 16-bit ID so an off-path attacker observing one timeout
// gets a fresh spoof window per retry rather than three guesses at the
// same target.
//
// The returned Message shares no mutable storage with m — section
// slices are cloned. EDNS is treated as immutable and shared.
func WithID(m Message, id uint16) Message {
	cp := &message{
		id:          id,
		flags:       m.Flags(),
		questions:   cloneSlice(m.Questions()),
		answers:     cloneSlice(m.Answers()),
		authorities: cloneSlice(m.Authorities()),
		additionals: cloneSlice(m.Additionals()),
	}
	if e, ok := m.EDNS(); ok {
		cp.edns = e
	}
	return cp
}

func (m *message) ID() uint16            { return m.id }
func (m *message) Flags() Flags          { return m.flags }
func (m *message) Questions() []Question { return slices.Clone(m.questions) }
func (m *message) Answers() []Record     { return slices.Clone(m.answers) }
func (m *message) Authorities() []Record { return slices.Clone(m.authorities) }
func (m *message) Additionals() []Record { return slices.Clone(m.additionals) }
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

	p := wirebb.NewPacker(make([]byte, 0, 64))
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
		return nil, &MessageParseError{
			Section: SectionHeader, Index: -1, Offset: len(buf),
			Cause: fmt.Errorf("header too short (%d bytes)", len(buf)),
		}
	}
	u := wirebb.NewUnpacker(buf)
	id, _ := u.Uint16()
	flags, _ := u.Uint16()
	qdcount, _ := u.Uint16()
	ancount, _ := u.Uint16()
	nscount, _ := u.Uint16()
	arcount, _ := u.Uint16()

	m := &message{id: id, flags: Flags(flags)}

	// Clamp the make capacities by what's actually parseable from the
	// remaining buffer. Without this, an attacker can send a 12-byte header
	// with all four count fields at 0xFFFF and force us to allocate four
	// huge slices before the first per-RR truncation error.
	remaining := u.Remaining()
	m.questions = make([]Question, 0, clampCount(int(qdcount), remaining, minQuestionSize))
	for i := range int(qdcount) {
		q, err := unpackQuestion(u)
		if err != nil {
			return nil, &MessageParseError{
				Section: SectionQuestion, Index: i, Offset: u.Off(), Cause: err,
			}
		}
		m.questions = append(m.questions, q)
	}
	if err := unpackRRs(u, &m.answers, int(ancount), SectionAnswer); err != nil {
		return nil, err
	}
	if err := unpackRRs(u, &m.authorities, int(nscount), SectionAuthority); err != nil {
		return nil, err
	}
	if err := unpackAdditionals(u, m, int(arcount)); err != nil {
		return nil, err
	}
	return m, nil
}

// minQuestionSize is the minimum on-the-wire size of a question:
// 1-byte root name + uint16 type + uint16 class.
const minQuestionSize = 5

// minRecordSize is the minimum on-the-wire size of a resource record:
// 1-byte root name + type + class + ttl + rdlen.
const minRecordSize = 11

// clampCount caps n at the number of structures of size minSize that could
// possibly fit in remaining bytes, preventing make capacity amplification
// from an attacker-controlled count field.
func clampCount(n, remaining, minSize int) int {
	if minSize <= 0 || remaining <= 0 {
		return 0
	}
	if upper := remaining / minSize; n > upper {
		return upper
	}
	return n
}

func unpackRRs(u *wirebb.Unpacker, dst *[]Record, n int, section Section) error {
	out := make([]Record, 0, clampCount(n, u.Remaining(), minRecordSize))
	for i := range n {
		r, err := unpackRecord(u)
		if err != nil {
			return &MessageParseError{
				Section: section, Index: i, Offset: u.Off(), Cause: err,
			}
		}
		out = append(out, r)
	}
	*dst = out
	return nil
}

// unpackAdditionals splits the additional section into regular records and
// the OPT pseudo-RR (if any).
func unpackAdditionals(u *wirebb.Unpacker, m *message, n int) error {
	out := make([]Record, 0, clampCount(n, u.Remaining(), minRecordSize))
	for i := range n {
		// Peek at the type without committing the unpacker.
		save := u.Off()
		if _, err := u.Name(); err != nil {
			return &MessageParseError{Section: SectionAdditional, Index: i, Offset: u.Off(), Cause: err}
		}
		t, err := u.Uint16()
		if err != nil {
			return &MessageParseError{Section: SectionAdditional, Index: i, Offset: u.Off(), Cause: err}
		}
		u.SetOff(save)

		if t == optTypeWire {
			if m.edns != nil {
				return &MessageParseError{
					Section: SectionOPT, Index: i, Offset: save,
					Cause: fmt.Errorf("multiple OPT pseudo-RRs"),
				}
			}
			e, err := unpackOPT(u)
			if err != nil {
				return &MessageParseError{Section: SectionOPT, Index: i, Offset: u.Off(), Cause: err}
			}
			m.edns = e
			continue
		}
		r, err := unpackRecord(u)
		if err != nil {
			return &MessageParseError{Section: SectionAdditional, Index: i, Offset: u.Off(), Cause: err}
		}
		out = append(out, r)
	}
	m.additionals = out
	return nil
}
