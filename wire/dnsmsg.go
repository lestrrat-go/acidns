package wire

import (
	"fmt"

	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// Message is a DNS protocol message. Value type — copy-friendly,
// returned by value from [Unmarshal] and [Builder.Build]. Construct
// via [NewMessageBuilder] so callers do not depend on field layout.
//
// # Section accessor semantics
//
// Accessors that return a section slice (Questions / Answers /
// Authorities / Additionals) ALIAS the Message's internal storage.
// Callers MUST NOT mutate the returned slice; [slices.Clone] the
// result if independent ownership is needed. The alias-by-default
// semantics avoids per-call allocations on hot paths (validator
// chain walks, AXFR streaming, middleware) where the caller is
// inspecting, not mutating.
type Message struct {
	id          uint16
	flags       Flags
	questions   []Question
	answers     []Record
	authorities []Record
	additionals []Record
	edns        EDNS
	hasEDNS     bool
}

// WithID returns a copy of m whose transaction ID has been replaced
// with id. Resolvers retry-loops use this to mint a fresh ID per
// outbound attempt: RFC 5452 §10 expects each fired query to draw an
// independent 16-bit ID so an off-path attacker observing one timeout
// gets a fresh spoof window per retry rather than three guesses at the
// same target.
//
// The returned Message's section slices ALIAS m's (consistent with
// the rest of the package's alias-by-default semantics — see
// [Message]). Section slices are never mutated through the public
// API of either value, so the alias is observationally equivalent
// to a clone for any caller that obeys the contract.
func WithID(m Message, id uint16) Message {
	// m is a value-receiver copy already (Go pass-by-value), so
	// mutating m.id here cannot affect the caller's variable —
	// it's idiomatic shorthand for "make a copy, change one field,
	// return the copy."
	m.id = id
	return m
}

// ID returns the transaction ID.
func (m Message) ID() uint16 { return m.id }

// Flags returns the message header flags.
func (m Message) Flags() Flags { return m.flags }

// Questions returns the question section. The returned slice ALIASES
// the Message's internal storage; callers MUST NOT mutate it.
// [slices.Clone] the result if independent ownership is needed.
func (m Message) Questions() []Question { return m.questions }

// Answers returns the answer section. Aliases internal storage —
// see [Message.Questions] for the alias-vs-clone contract.
func (m Message) Answers() []Record { return m.answers }

// Authorities returns the authority section. Aliases internal storage.
func (m Message) Authorities() []Record { return m.authorities }

// Additionals returns the additional section, excluding any OPT
// pseudo-RR (surfaced via [Message.EDNS]). Aliases internal storage.
func (m Message) Additionals() []Record { return m.additionals }

// EDNS returns the parsed OPT payload and a bool indicating whether
// the message carried one.
func (m Message) EDNS() (EDNS, bool) { return m.edns, m.hasEDNS }

// Marshal encodes m to a single DNS wire-format datagram, using compression
// for repeated name suffixes.
func Marshal(m Message) ([]byte, error) {
	if len(m.questions) > 0xffff || len(m.answers) > 0xffff ||
		len(m.authorities) > 0xffff || len(m.additionals) > 0xffff {
		return nil, fmt.Errorf("%w: section count overflow", ErrInvalidMessage)
	}

	arcount := len(m.additionals)
	if m.hasEDNS {
		arcount++
	}

	p := wirebb.NewPacker(make([]byte, 0, 64))
	p.Uint16(m.id)
	p.Uint16(uint16(m.flags))
	p.Uint16(uint16(len(m.questions)))
	p.Uint16(uint16(len(m.answers)))
	p.Uint16(uint16(len(m.authorities)))
	p.Uint16(uint16(arcount))

	for _, q := range m.questions {
		packQuestion(p, q)
	}
	for _, r := range m.answers {
		if err := packRecord(p, r); err != nil {
			return nil, err
		}
	}
	for _, r := range m.authorities {
		if err := packRecord(p, r); err != nil {
			return nil, err
		}
	}
	for _, r := range m.additionals {
		if err := packRecord(p, r); err != nil {
			return nil, err
		}
	}
	if m.hasEDNS {
		if err := packOPT(p, m.edns); err != nil {
			return nil, err
		}
	}
	out := p.Bytes()
	// A TCP frame's 16-bit length prefix caps the whole message at
	// 65535 bytes; UDP can carry less still. streamframe.WriteFrame
	// catches the TCP case at send time, but raw-UDP / raw-buffer
	// callers do not — enforce the hard wire limit here so an
	// oversize Marshal fails loudly rather than producing bytes no
	// transport can carry.
	if len(out) > 0xffff {
		return nil, fmt.Errorf("%w: message %d bytes exceeds wire limit (65535)", ErrInvalidMessage, len(out))
	}
	return out, nil
}

// Unmarshal decodes a wire-format DNS message.
func Unmarshal(buf []byte) (Message, error) {
	if len(buf) < 12 {
		return Message{}, NewMessageParseError(
			SectionHeader, -1, len(buf),
			fmt.Errorf("header too short (%d bytes)", len(buf)),
		)
	}
	u := wirebb.NewUnpacker(buf)
	id, _ := u.Uint16()
	flags, _ := u.Uint16()
	qdcount, _ := u.Uint16()
	ancount, _ := u.Uint16()
	nscount, _ := u.Uint16()
	arcount, _ := u.Uint16()

	m := Message{id: id, flags: Flags(flags)}

	// Clamp the make capacities by what's actually parseable from the
	// remaining buffer. Without this, an attacker can send a 12-byte header
	// with all four count fields at 0xFFFF and force us to allocate four
	// huge slices before the first per-RR truncation error.
	remaining := u.Remaining()
	m.questions = make([]Question, 0, clampCount(int(qdcount), remaining, minQuestionSize))
	for i := range int(qdcount) {
		q, err := unpackQuestion(u)
		if err != nil {
			return Message{}, NewMessageParseError(SectionQuestion, i, u.Off(), err)
		}
		m.questions = append(m.questions, q)
	}
	if err := unpackRRs(u, &m.answers, int(ancount), SectionAnswer); err != nil {
		return Message{}, err
	}
	if err := unpackRRs(u, &m.authorities, int(nscount), SectionAuthority); err != nil {
		return Message{}, err
	}
	if err := unpackAdditionals(u, &m, int(arcount)); err != nil {
		return Message{}, err
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
			return NewMessageParseError(section, i, u.Off(), err)
		}
		out = append(out, r)
	}
	*dst = out
	return nil
}

// unpackAdditionals splits the additional section into regular records and
// the OPT pseudo-RR (if any).
func unpackAdditionals(u *wirebb.Unpacker, m *Message, n int) error {
	out := make([]Record, 0, clampCount(n, u.Remaining(), minRecordSize))
	for i := range n {
		// Peek at the type without committing the unpacker.
		save := u.Off()
		if _, err := u.Name(); err != nil {
			return NewMessageParseError(SectionAdditional, i, u.Off(), err)
		}
		t, err := u.Uint16()
		if err != nil {
			return NewMessageParseError(SectionAdditional, i, u.Off(), err)
		}
		u.SetOff(save)

		if t == optTypeWire {
			if m.hasEDNS {
				return NewMessageParseError(
					SectionOPT, i, save,
					fmt.Errorf("multiple OPT pseudo-RRs"),
				)
			}
			e, err := unpackOPT(u)
			if err != nil {
				return NewMessageParseError(SectionOPT, i, u.Off(), err)
			}
			m.edns = e
			m.hasEDNS = true
			continue
		}
		r, err := unpackRecord(u)
		if err != nil {
			return NewMessageParseError(SectionAdditional, i, u.Off(), err)
		}
		out = append(out, r)
	}
	m.additionals = out
	return nil
}
