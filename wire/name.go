package wire

import "github.com/lestrrat-go/acidns/wire/wirebb"

// Name is the DNS domain name type — see [wirebb.Name] for the full
// documentation. It is re-exported here as an alias so user code can refer to
// it as `wire.Name` alongside `wire.Message` and friends.
type Name = wirebb.Name

// ErrInvalidName is returned when a name fails parsing or wire decoding.
var ErrInvalidName = wirebb.ErrInvalidName

// ParseName parses a textual presentation-form name into a Name.
func ParseName(s string) (Name, error) { return wirebb.Parse(s) }

// MustParseName is like [ParseName] but panics on error. For tests, fixtures,
// and constants only.
func MustParseName(s string) Name { return wirebb.MustParse(s) }

// RootName returns the DNS root name (".").
func RootName() Name { return wirebb.Root() }

// NameFromLabels constructs a Name from individual labels.
func NameFromLabels(labels ...string) (Name, error) { return wirebb.FromLabels(labels...) }

// DecodeName decodes a domain name from msg starting at off, following any
// compression pointers, and returns the Name and the offset of the byte
// after the on-the-wire encoding (not after pointer targets).
func DecodeName(msg []byte, off int) (Name, int, error) { return wirebb.DecodeWire(msg, off) }
