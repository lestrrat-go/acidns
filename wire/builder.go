package wire

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
	err         error
}

// NewBuilder returns a fresh Builder.
func NewBuilder() *Builder { return &Builder{} }

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
func (b *Builder) Answer(r Record) *Builder     { b.answers = append(b.answers, r); return b }
func (b *Builder) Authority(r Record) *Builder  { b.authorities = append(b.authorities, r); return b }
func (b *Builder) Additional(r Record) *Builder { b.additionals = append(b.additionals, r); return b }
func (b *Builder) EDNS(e EDNS) *Builder         { b.edns = e; return b }

func (b *Builder) Build() (Message, error) {
	if b.err != nil {
		return nil, b.err
	}
	return &message{
		id:          b.id,
		flags:       b.flags,
		questions:   b.questions,
		answers:     b.answers,
		authorities: b.authorities,
		additionals: b.additionals,
		edns:        b.edns,
	}, nil
}
