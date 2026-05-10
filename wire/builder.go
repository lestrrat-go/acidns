package wire

import "fmt"

// Builder constructs a Message in stages. All setter methods return the
// receiver so calls can be chained; Build returns the immutable Message.
//
// Errors accumulated by the Builder (e.g. mismatched section sizes after
// future EDNS handling is added) are surfaced from Build.
//
// A Builder is owned by a single goroutine and is NOT safe for concurrent
// use. The Message returned by Build is immutable and may be shared.
type Builder struct {
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

// NewMessageBuilder returns a fresh Builder.
func NewMessageBuilder() *Builder { return &Builder{} }

func (b *Builder) ID(v uint16) *Builder     { b.id = v; return b }
func (b *Builder) Flags(f Flags) *Builder   { b.flags = f; return b }
func (b *Builder) Response(v bool) *Builder { b.flags = b.flags.WithResponse(v); return b }
func (b *Builder) Opcode(o Opcode) *Builder { b.flags = b.flags.WithOpcode(o); return b }
func (b *Builder) Authoritative(v bool) *Builder {
	b.flags = b.flags.WithAuthoritative(v)
	return b
}
func (b *Builder) Truncated(v bool) *Builder { b.flags = b.flags.WithTruncated(v); return b }
func (b *Builder) RecursionDesired(v bool) *Builder {
	b.flags = b.flags.WithRecursionDesired(v)
	return b
}
func (b *Builder) RecursionAvailable(v bool) *Builder {
	b.flags = b.flags.WithRecursionAvailable(v)
	return b
}
func (b *Builder) AuthenticData(v bool) *Builder {
	b.flags = b.flags.WithAuthenticData(v)
	return b
}
func (b *Builder) CheckingDisabled(v bool) *Builder {
	b.flags = b.flags.WithCheckingDisabled(v)
	return b
}
func (b *Builder) RCODE(r RCODE) *Builder       { b.flags = b.flags.WithRCODE(r); return b }
func (b *Builder) Question(q Question) *Builder { b.questions = append(b.questions, q); return b }

// Answer appends a Record to the answer section. A zero-value Record
// (no rdata attached) is rejected — Marshal would panic on the nil
// rdata interface, so failing fast here surfaces the bug at the build
// site instead of deep inside the encoder.
func (b *Builder) Answer(r Record) *Builder {
	if r.IsZero() {
		b.setErr(fmt.Errorf("wire: Builder.Answer received zero Record"))
		return b
	}
	b.answers = append(b.answers, r)
	return b
}

// Authority appends a Record to the authority section. See [Builder.Answer]
// for the zero-Record rejection rationale.
func (b *Builder) Authority(r Record) *Builder {
	if r.IsZero() {
		b.setErr(fmt.Errorf("wire: Builder.Authority received zero Record"))
		return b
	}
	b.authorities = append(b.authorities, r)
	return b
}

// Additional appends a Record to the additional section. See
// [Builder.Answer] for the zero-Record rejection rationale.
func (b *Builder) Additional(r Record) *Builder {
	if r.IsZero() {
		b.setErr(fmt.Errorf("wire: Builder.Additional received zero Record"))
		return b
	}
	b.additionals = append(b.additionals, r)
	return b
}
func (b *Builder) EDNS(e EDNS) *Builder { b.edns = e; b.hasEDNS = true; return b }

// setErr stores the first error seen by the Builder so subsequent
// chained calls can keep returning b without obscuring the original
// failure.
func (b *Builder) setErr(err error) {
	if b.err == nil {
		b.err = err
	}
}

func (b *Builder) Build() (Message, error) {
	if b.err != nil {
		return Message{}, b.err
	}
	// Snapshot every section into a freshly-allocated slice. Without this
	// step a Builder reused after Build (b.Answer(...).Build() then more
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
