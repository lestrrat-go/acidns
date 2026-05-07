package zonefile

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// tokenKind enumerates the lexical categories produced by the lexer.
type tokenKind int

const (
	tokWord   tokenKind = iota // bare word (no whitespace, may be a directive starting with $)
	tokQuoted                  // "quoted string"
	tokEOL                     // end of logical line (after closing all parens)
	tokEOF
)

// token carries one lexical unit.
type token struct {
	kind tokenKind
	text string
	line int
}

// lexer reads a master file as a stream of tokens. It collapses runs of
// whitespace, hides comments, and treats parenthesised regions as part of a
// single logical line.
//
// State machine:
//
//	inLine          : at least one token has been emitted on this logical line
//	sawLeadingWS    : at least one ' ' or '\t' was read before any token of the
//	                  current logical line
//	parenDepth      : unbalanced '(' count
type lexer struct {
	r            *bufio.Reader
	line         int
	parenDepth   int
	inLine       bool
	sawLeadingWS bool
}

func newLexer(r io.Reader) *lexer {
	return &lexer{r: bufio.NewReader(r), line: 1}
}

// next returns the next token together with a leadingWS flag that is only
// meaningful for the first non-EOL token of each logical line.
func (l *lexer) next() (token, bool, error) {
	for {
		b, err := l.r.ReadByte()
		if err == io.EOF {
			if l.parenDepth != 0 {
				return token{}, false, fmt.Errorf("line %d: unbalanced parentheses at EOF", l.line)
			}
			if l.inLine {
				l.inLine = false
				l.sawLeadingWS = false
				return token{kind: tokEOL, line: l.line}, false, nil
			}
			return token{kind: tokEOF, line: l.line}, false, nil
		}
		if err != nil {
			return token{}, false, err
		}
		switch b {
		case '\r':
			// drop
		case '\n':
			l.line++
			if l.parenDepth == 0 && l.inLine {
				l.inLine = false
				l.sawLeadingWS = false
				return token{kind: tokEOL, line: l.line - 1}, false, nil
			}
			// otherwise: in parens, or empty line — keep going
		case ' ', '\t':
			if !l.inLine {
				l.sawLeadingWS = true
			}
		case ';':
			// comment to end of physical line
			for {
				c, err := l.r.ReadByte()
				if err == io.EOF {
					return l.flushOnEOF()
				}
				if err != nil {
					return token{}, false, err
				}
				if c == '\n' {
					l.line++
					if l.parenDepth == 0 && l.inLine {
						l.inLine = false
						l.sawLeadingWS = false
						return token{kind: tokEOL, line: l.line - 1}, false, nil
					}
					break
				}
			}
		case '(':
			l.parenDepth++
		case ')':
			if l.parenDepth == 0 {
				return token{}, false, fmt.Errorf("line %d: unexpected ')'", l.line)
			}
			l.parenDepth--
		case '"':
			s, err := l.readQuoted()
			if err != nil {
				return token{}, false, err
			}
			leading := l.sawLeadingWS && !l.inLine
			l.inLine = true
			return token{kind: tokQuoted, text: s, line: l.line}, leading, nil
		default:
			if err := l.r.UnreadByte(); err != nil {
				return token{}, false, err
			}
			s, err := l.readWord()
			if err != nil {
				return token{}, false, err
			}
			leading := l.sawLeadingWS && !l.inLine
			l.inLine = true
			return token{kind: tokWord, text: s, line: l.line}, leading, nil
		}
	}
}

func (l *lexer) flushOnEOF() (token, bool, error) {
	if l.inLine {
		l.inLine = false
		l.sawLeadingWS = false
		return token{kind: tokEOL, line: l.line}, false, nil
	}
	return token{kind: tokEOF, line: l.line}, false, nil
}

func (l *lexer) readWord() (string, error) {
	var sb strings.Builder
	for {
		b, err := l.r.ReadByte()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		switch b {
		case ' ', '\t', '\n', '\r', ';', '(', ')', '"':
			if err := l.r.UnreadByte(); err != nil {
				return "", err
			}
			return sb.String(), nil
		case '\\':
			c, err := l.r.ReadByte()
			if err != nil {
				return "", fmt.Errorf("line %d: dangling backslash", l.line)
			}
			sb.WriteByte('\\')
			sb.WriteByte(c)
		default:
			sb.WriteByte(b)
		}
	}
	return sb.String(), nil
}

func (l *lexer) readQuoted() (string, error) {
	var sb strings.Builder
	for {
		b, err := l.r.ReadByte()
		if err == io.EOF {
			return "", fmt.Errorf("line %d: unterminated quoted string", l.line)
		}
		if err != nil {
			return "", err
		}
		switch b {
		case '"':
			return sb.String(), nil
		case '\\':
			c, err := l.r.ReadByte()
			if err != nil {
				return "", fmt.Errorf("line %d: dangling backslash in quoted string", l.line)
			}
			sb.WriteByte(c)
		case '\n':
			l.line++
			sb.WriteByte(b)
		default:
			sb.WriteByte(b)
		}
	}
}
