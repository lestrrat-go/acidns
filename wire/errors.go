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
	section Section
	index   int
	offset  int
	cause   error
}

func NewMessageParseError(section Section, index, offset int, cause error) *MessageParseError {
	return &MessageParseError{section: section, index: index, offset: offset, cause: cause}
}

// Section returns the message section in which the failure originated.
func (e *MessageParseError) Section() Section { return e.section }

// Index returns the 0-based RR position within the section. -1 when not
// applicable (header parse, section count overflow).
func (e *MessageParseError) Index() int { return e.index }

// Offset returns the byte position into the input buffer at which the
// failure was detected. -1 when not tracked.
func (e *MessageParseError) Offset() int { return e.offset }

// Cause returns the underlying error.
func (e *MessageParseError) Cause() error { return e.cause }

// Error renders a human-readable summary. The Cause is included so that
// fmt.Errorf("...: %w", err) chains read as expected; structured fields
// are emitted only when non-default.
func (e *MessageParseError) Error() string {
	var prefix string
	switch {
	case e.section == SectionUnknown && e.index < 0:
		prefix = "parse"
	case e.index < 0:
		prefix = fmt.Sprintf("parse %s", e.section)
	default:
		prefix = fmt.Sprintf("parse %s[%d]", e.section, e.index)
	}
	if e.offset >= 0 {
		prefix += fmt.Sprintf(" at offset %d", e.offset)
	}
	if e.cause == nil {
		return "wire: " + prefix
	}
	return fmt.Sprintf("wire: %s: %s", prefix, e.cause)
}

// Unwrap returns the underlying cause so errors.As / errors.Is can reach
// further into the chain.
func (e *MessageParseError) Unwrap() error { return e.cause }

// Is matches against ErrInvalidMessage so legacy callers that check
// errors.Is(err, ErrInvalidMessage) continue to work without taking a
// dependency on the new typed error.
func (e *MessageParseError) Is(target error) bool {
	return errors.Is(target, ErrInvalidMessage)
}
