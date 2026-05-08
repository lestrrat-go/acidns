// (See package wirebb's main doc.go for the package-level overview.)
//
// A Name is an immutable, fully-qualified domain name held as its canonical
// lowercase wire encoding. The zero Name is invalid; the root name "." is
// distinct and obtained via Root(), Parse("."), or FromLabels().
package wirebb

import (
	"errors"
	"fmt"
	"iter"
	"strings"
)

const (
	maxLabelLen = 63
	maxNameLen  = 255
	maxPtrHops  = 32
)

// ErrInvalidName is returned when a name fails parsing or wire decoding.
var ErrInvalidName = errors.New("wirebb: invalid name")

// Name is a DNS domain name. The zero value is invalid.
//
// Internally a Name holds the canonical lowercase wire encoding of the
// fully-qualified name (a sequence of length-prefixed labels terminated by a
// zero-length label). Two Names are Equal iff their wire encodings are equal,
// which makes comparison case-insensitive without re-folding.
type Name struct {
	wire string
}

// IsValid reports whether n is a usable Name (i.e. not the zero value).
func (n Name) IsValid() bool { return len(n.wire) > 0 }

// IsRoot reports whether n is the DNS root (".").
func (n Name) IsRoot() bool { return n.wire == "\x00" }

// NumLabels returns the number of labels in n, excluding the implicit root.
// Root has 0 labels, "example.com." has 2.
func (n Name) NumLabels() int {
	if !n.IsValid() {
		return 0
	}
	count := 0
	for off := 0; off < len(n.wire); {
		l := int(n.wire[off])
		if l == 0 {
			break
		}
		count++
		off += 1 + l
	}
	return count
}

// Labels returns an iterator over the wire-format labels of n. The yielded
// byte slices alias the receiver's internal storage; do not modify them.
func (n Name) Labels() iter.Seq[[]byte] {
	return func(yield func([]byte) bool) {
		if !n.IsValid() {
			return
		}
		for off := 0; off < len(n.wire); {
			l := int(n.wire[off])
			if l == 0 {
				return
			}
			if !yield([]byte(n.wire[off+1 : off+1+l])) {
				return
			}
			off += 1 + l
		}
	}
}

// Parent returns the parent zone of n. Root has no parent.
func (n Name) Parent() (Name, bool) {
	if !n.IsValid() || n.IsRoot() {
		return Name{}, false
	}
	first := int(n.wire[0])
	return Name{wire: n.wire[1+first:]}, true
}

// Equal reports whether n and o are the same name.
func (n Name) Equal(o Name) bool { return n.wire == o.wire }

// String returns the textual representation of n with a trailing dot.
// The zero Name renders as the empty string.
func (n Name) String() string {
	if !n.IsValid() {
		return ""
	}
	if n.IsRoot() {
		return "."
	}
	var b strings.Builder
	b.Grow(len(n.wire))
	for off := 0; off < len(n.wire); {
		l := int(n.wire[off])
		if l == 0 {
			break
		}
		for i := off + 1; i < off+1+l; i++ {
			c := n.wire[i]
			switch {
			case c == '.' || c == '\\':
				b.WriteByte('\\')
				b.WriteByte(c)
			case c < 0x21 || c > 0x7e:
				fmt.Fprintf(&b, `\%03d`, c)
			default:
				b.WriteByte(c)
			}
		}
		b.WriteByte('.')
		off += 1 + l
	}
	return b.String()
}

// AppendWire appends the uncompressed wire encoding of n to buf and returns
// the extended slice.
func (n Name) AppendWire(buf []byte) []byte {
	if !n.IsValid() {
		return append(buf, 0)
	}
	return append(buf, n.wire...)
}

// WireLen returns the length in bytes of n's uncompressed wire encoding.
func (n Name) WireLen() int {
	if !n.IsValid() {
		return 1
	}
	return len(n.wire)
}

// Root returns the DNS root name ".".
func Root() Name { return Name{wire: "\x00"} }

// MustParse is like Parse but panics on error.
func MustParse(s string) Name {
	n, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return n
}

// Parse parses s as a DNS domain name. It accepts presentation form with or
// without a trailing dot, lowercases ASCII letters, and recognises the
// standard backslash escapes (`\.`, `\\`, `\DDD`).
func Parse(s string) (Name, error) {
	if s == "" {
		return Name{}, fmt.Errorf("%w: empty", ErrInvalidName)
	}
	if s == "." {
		return Root(), nil
	}

	wire := make([]byte, 0, len(s)+2)
	label := make([]byte, 0, maxLabelLen)

	flush := func() error {
		if len(label) == 0 {
			return fmt.Errorf("%w: empty label", ErrInvalidName)
		}
		if len(label) > maxLabelLen {
			return fmt.Errorf("%w: label exceeds %d bytes", ErrInvalidName, maxLabelLen)
		}
		wire = append(wire, byte(len(label)))
		wire = append(wire, label...)
		label = label[:0]
		return nil
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '.':
			if err := flush(); err != nil {
				return Name{}, err
			}
		case '\\':
			if i+1 >= len(s) {
				return Name{}, fmt.Errorf("%w: trailing backslash", ErrInvalidName)
			}
			next := s[i+1]
			if next >= '0' && next <= '9' {
				if i+3 >= len(s) {
					return Name{}, fmt.Errorf("%w: truncated decimal escape", ErrInvalidName)
				}
				d2, d3 := s[i+2], s[i+3]
				if d2 < '0' || d2 > '9' || d3 < '0' || d3 > '9' {
					return Name{}, fmt.Errorf("%w: bad decimal escape", ErrInvalidName)
				}
				v := int(next-'0')*100 + int(d2-'0')*10 + int(d3-'0')
				if v > 255 {
					return Name{}, fmt.Errorf("%w: decimal escape > 255", ErrInvalidName)
				}
				label = append(label, byte(v))
				i += 3
			} else {
				label = append(label, foldByte(next))
				i++
			}
		default:
			label = append(label, foldByte(c))
		}
	}
	if len(label) > 0 {
		if err := flush(); err != nil {
			return Name{}, err
		}
	}
	wire = append(wire, 0)
	if len(wire) > maxNameLen {
		return Name{}, fmt.Errorf("%w: name exceeds %d bytes", ErrInvalidName, maxNameLen)
	}
	return Name{wire: string(wire)}, nil
}

// FromLabels constructs a Name from raw label bytes (no escape processing).
// An empty list yields the root.
func FromLabels(labels ...string) (Name, error) {
	if len(labels) == 0 {
		return Root(), nil
	}
	wire := make([]byte, 0, 1)
	for _, l := range labels {
		if len(l) == 0 {
			return Name{}, fmt.Errorf("%w: empty label", ErrInvalidName)
		}
		if len(l) > maxLabelLen {
			return Name{}, fmt.Errorf("%w: label exceeds %d bytes", ErrInvalidName, maxLabelLen)
		}
		wire = append(wire, byte(len(l)))
		for i := range len(l) {
			wire = append(wire, foldByte(l[i]))
		}
	}
	wire = append(wire, 0)
	if len(wire) > maxNameLen {
		return Name{}, fmt.Errorf("%w: name exceeds %d bytes", ErrInvalidName, maxNameLen)
	}
	return Name{wire: string(wire)}, nil
}

// DecodeWire decodes a wire-format name from msg starting at off, following
// compression pointers. It returns the decoded Name and the offset of the
// first byte after the on-the-wire name encoding (which, in the presence of
// pointers, may be earlier in the message than where the name fully resolves).
func DecodeWire(msg []byte, off int) (Name, int, error) {
	if off < 0 || off >= len(msg) {
		return Name{}, 0, fmt.Errorf("%w: offset %d out of range", ErrInvalidName, off)
	}

	out := make([]byte, 0, 64)
	cur := off
	nextOff := -1
	hops := 0
	total := 0

	for {
		if cur >= len(msg) {
			return Name{}, 0, fmt.Errorf("%w: truncated", ErrInvalidName)
		}
		b := msg[cur]
		switch b & 0xc0 {
		case 0x00:
			l := int(b)
			if l == 0 {
				out = append(out, 0)
				if nextOff < 0 {
					nextOff = cur + 1
				}
				if total+1 > maxNameLen {
					return Name{}, 0, fmt.Errorf("%w: name exceeds %d bytes", ErrInvalidName, maxNameLen)
				}
				return Name{wire: string(out)}, nextOff, nil
			}
			if cur+1+l > len(msg) {
				return Name{}, 0, fmt.Errorf("%w: truncated label", ErrInvalidName)
			}
			total += 1 + l
			if total > maxNameLen {
				return Name{}, 0, fmt.Errorf("%w: name exceeds %d bytes", ErrInvalidName, maxNameLen)
			}
			out = append(out, byte(l))
			for i := cur + 1; i < cur+1+l; i++ {
				out = append(out, foldByte(msg[i]))
			}
			cur += 1 + l
		case 0xc0:
			if cur+1 >= len(msg) {
				return Name{}, 0, fmt.Errorf("%w: truncated pointer", ErrInvalidName)
			}
			ptr := int(b&0x3f)<<8 | int(msg[cur+1])
			if nextOff < 0 {
				nextOff = cur + 2
			}
			if ptr >= cur {
				return Name{}, 0, fmt.Errorf("%w: forward or self pointer", ErrInvalidName)
			}
			hops++
			if hops > maxPtrHops {
				return Name{}, 0, fmt.Errorf("%w: pointer loop", ErrInvalidName)
			}
			cur = ptr
		default:
			return Name{}, 0, fmt.Errorf("%w: reserved label type 0x%02x", ErrInvalidName, b&0xc0)
		}
	}
}

func foldByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
