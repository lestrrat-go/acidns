package wire

import (
	"errors"
	"fmt"
)

// Section identifies which DNS message section a parse failure originated
// in. It is exposed on MessageParseError so tools can render the failure
// with the right surrounding context.
type Section uint8

// Section values. SectionUnknown is the zero value and means the parser
// has not yet committed to a section (e.g. the header itself failed to
// parse) or that the section context was not preserved.
const (
	SectionUnknown Section = iota
	SectionHeader
	SectionQuestion
	SectionAnswer
	SectionAuthority
	SectionAdditional
	SectionOPT
)

func (s Section) String() string {
	switch s {
	case SectionHeader:
		return "header"
	case SectionQuestion:
		return "question"
	case SectionAnswer:
		return "answer"
	case SectionAuthority:
		return "authority"
	case SectionAdditional:
		return "additional"
	case SectionOPT:
		return "opt"
	default:
		return "unknown"
	}
}

// MessageParseError carries structured context about a failure in
// wire.Unmarshal. Tools that want to render a hex-dump pointer at the
// offending byte (acidig, fuzz harnesses) can read Offset; consumers
// content with a sentinel still get errors.Is(err, ErrInvalidMessage)
// because Is matches the sentinel.
type MessageParseError struct {
	Section Section
	// Index is the 0-based RR position within the section. -1 when not
	// applicable (header parse, section count overflow).
	Index int
	// Offset is the byte position into the input buffer at which the
	// failure was detected. -1 when not tracked.
	Offset int
	Cause  error
}

// Error renders a human-readable summary. The Cause is included so that
// fmt.Errorf("...: %w", err) chains read as expected; structured fields
// are emitted only when non-default.
func (e *MessageParseError) Error() string {
	var prefix string
	switch {
	case e.Section == SectionUnknown && e.Index < 0:
		prefix = "parse"
	case e.Index < 0:
		prefix = fmt.Sprintf("parse %s", e.Section)
	default:
		prefix = fmt.Sprintf("parse %s[%d]", e.Section, e.Index)
	}
	if e.Offset >= 0 {
		prefix += fmt.Sprintf(" at offset %d", e.Offset)
	}
	if e.Cause == nil {
		return "wire: " + prefix
	}
	return fmt.Sprintf("wire: %s: %s", prefix, e.Cause)
}

// Unwrap returns the underlying cause so errors.As / errors.Is can reach
// further into the chain.
func (e *MessageParseError) Unwrap() error { return e.Cause }

// Is matches against ErrInvalidMessage so legacy callers that check
// errors.Is(err, ErrInvalidMessage) continue to work without taking a
// dependency on the new typed error.
func (e *MessageParseError) Is(target error) bool {
	return errors.Is(target, ErrInvalidMessage)
}
