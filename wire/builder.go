package wire

// Builder constructs a Message in stages. All setter methods return the
// receiver so calls can be chained; Build returns the immutable Message.
//
// Errors accumulated by the Builder (e.g. mismatched section sizes after
// future EDNS handling is added) are surfaced from Build.
type Builder interface { //nolint:interfacebloat // builder fluent API
	ID(uint16) Builder
	Flags(Flags) Builder
	Response(bool) Builder
	Opcode(Opcode) Builder
	Authoritative(bool) Builder
	Truncated(bool) Builder
	RecursionDesired(bool) Builder
	RecursionAvailable(bool) Builder
	AuthenticData(bool) Builder
	CheckingDisabled(bool) Builder
	RCODE(RCODE) Builder
	Question(Question) Builder
	Answer(Record) Builder
	Authority(Record) Builder
	Additional(Record) Builder
	EDNS(EDNS) Builder
	Build() (Message, error)
}

type builder struct {
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
func NewBuilder() Builder { return &builder{} }

func (b *builder) ID(v uint16) Builder     { b.id = v; return b }
func (b *builder) Flags(f Flags) Builder   { b.flags = f; return b }
func (b *builder) Response(v bool) Builder { b.flags = b.flags.WithResponse(v); return b }
func (b *builder) Opcode(o Opcode) Builder { b.flags = b.flags.WithOpcode(o); return b }
func (b *builder) Authoritative(v bool) Builder {
	b.flags = b.flags.WithAuthoritative(v)
	return b
}
func (b *builder) Truncated(v bool) Builder { b.flags = b.flags.WithTruncated(v); return b }
func (b *builder) RecursionDesired(v bool) Builder {
	b.flags = b.flags.WithRecursionDesired(v)
	return b
}
func (b *builder) RecursionAvailable(v bool) Builder {
	b.flags = b.flags.WithRecursionAvailable(v)
	return b
}
func (b *builder) AuthenticData(v bool) Builder {
	b.flags = b.flags.WithAuthenticData(v)
	return b
}
func (b *builder) CheckingDisabled(v bool) Builder {
	b.flags = b.flags.WithCheckingDisabled(v)
	return b
}
func (b *builder) RCODE(r RCODE) Builder       { b.flags = b.flags.WithRCODE(r); return b }
func (b *builder) Question(q Question) Builder { b.questions = append(b.questions, q); return b }
func (b *builder) Answer(r Record) Builder     { b.answers = append(b.answers, r); return b }
func (b *builder) Authority(r Record) Builder  { b.authorities = append(b.authorities, r); return b }
func (b *builder) Additional(r Record) Builder { b.additionals = append(b.additionals, r); return b }
func (b *builder) EDNS(e EDNS) Builder         { b.edns = e; return b }

func (b *builder) Build() (Message, error) {
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
