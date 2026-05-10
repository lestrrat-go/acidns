package wire

import "fmt"

// MessageBuilder constructs a Message in stages. All setter methods return the
// receiver so calls can be chained; Build returns the immutable Message.
//
// Errors accumulated by the MessageBuilder (e.g. mismatched section sizes after
// future EDNS handling is added) are surfaced from Build.
//
// A MessageBuilder is owned by a single goroutine and is NOT safe for concurrent
// use. The Message returned by Build is immutable and may be shared.
type MessageBuilder struct {
	id          uint16
	flags       Flags
	questions   []Question
	answers     []Record
	authorities []Record
	additionals []Record
	edns        EDNS
	hasEDNS     bool
	err         error
}

// NewMessageMessageBuilder returns a fresh MessageBuilder.
func NewMessageBuilder() *MessageBuilder { return &MessageBuilder{} }

func (b *MessageBuilder) ID(v uint16) *MessageBuilder     { b.id = v; return b }
func (b *MessageBuilder) Flags(f Flags) *MessageBuilder   { b.flags = f; return b }
func (b *MessageBuilder) Response(v bool) *MessageBuilder { b.flags = b.flags.WithResponse(v); return b }
func (b *MessageBuilder) Opcode(o Opcode) *MessageBuilder { b.flags = b.flags.WithOpcode(o); return b }
func (b *MessageBuilder) Authoritative(v bool) *MessageBuilder {
	b.flags = b.flags.WithAuthoritative(v)
	return b
}
func (b *MessageBuilder) Truncated(v bool) *MessageBuilder { b.flags = b.flags.WithTruncated(v); return b }
func (b *MessageBuilder) RecursionDesired(v bool) *MessageBuilder {
	b.flags = b.flags.WithRecursionDesired(v)
	return b
}
func (b *MessageBuilder) RecursionAvailable(v bool) *MessageBuilder {
	b.flags = b.flags.WithRecursionAvailable(v)
	return b
}
func (b *MessageBuilder) AuthenticData(v bool) *MessageBuilder {
	b.flags = b.flags.WithAuthenticData(v)
	return b
}
func (b *MessageBuilder) CheckingDisabled(v bool) *MessageBuilder {
	b.flags = b.flags.WithCheckingDisabled(v)
	return b
}
func (b *MessageBuilder) RCODE(r RCODE) *MessageBuilder       { b.flags = b.flags.WithRCODE(r); return b }
func (b *MessageBuilder) Question(q Question) *MessageBuilder { b.questions = append(b.questions, q); return b }

// Answer appends a Record to the answer section. A zero-value Record
// (no rdata attached) is rejected — Marshal would panic on the nil
// rdata interface, so failing fast here surfaces the bug at the build
// site instead of deep inside the encoder.
func (b *MessageBuilder) Answer(r Record) *MessageBuilder {
	if r.IsZero() {
		b.setErr(fmt.Errorf("wire: MessageBuilder.Answer received zero Record"))
		return b
	}
	b.answers = append(b.answers, r)
	return b
}

// Authority appends a Record to the authority section. See [MessageBuilder.Answer]
// for the zero-Record rejection rationale.
func (b *MessageBuilder) Authority(r Record) *MessageBuilder {
	if r.IsZero() {
		b.setErr(fmt.Errorf("wire: MessageBuilder.Authority received zero Record"))
		return b
	}
	b.authorities = append(b.authorities, r)
	return b
}

// Additional appends a Record to the additional section. See
// [MessageBuilder.Answer] for the zero-Record rejection rationale.
func (b *MessageBuilder) Additional(r Record) *MessageBuilder {
	if r.IsZero() {
		b.setErr(fmt.Errorf("wire: MessageBuilder.Additional received zero Record"))
		return b
	}
	b.additionals = append(b.additionals, r)
	return b
}
func (b *MessageBuilder) EDNS(e EDNS) *MessageBuilder { b.edns = e; b.hasEDNS = true; return b }

// setErr stores the first error seen by the MessageBuilder so subsequent
// chained calls can keep returning b without obscuring the original
// failure.
func (b *MessageBuilder) setErr(err error) {
	if b.err == nil {
		b.err = err
	}
}

func (b *MessageBuilder) Build() (Message, error) {
	if b.err != nil {
		return Message{}, b.err
	}
	// Snapshot every section into a freshly-allocated slice. Without this
	// step a MessageBuilder reused after Build (b.Answer(...).Build() then more
	// b.Answer(...).Build()) could mutate the first Message's backing
	// array via append's grow-in-place semantics. The package contract
	// promises Build returns an immutable Message; the copy enforces it.
	return Message{
		id:          b.id,
		flags:       b.flags,
		questions:   cloneSlice(b.questions),
		answers:     cloneSlice(b.answers),
		authorities: cloneSlice(b.authorities),
		additionals: cloneSlice(b.additionals),
		edns:        b.edns,
		hasEDNS:     b.hasEDNS,
	}, nil
}

// cloneSlice returns a fresh slice with the same elements as s, or nil
// when s is empty so the zero-record sections continue to compare equal
// against the nil literal in tests.
func cloneSlice[T any](s []T) []T {
	if len(s) == 0 {
		return nil
	}
	out := make([]T, len(s))
	copy(out, s)
	return out
}
