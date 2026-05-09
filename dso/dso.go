// Package dso encodes and decodes DNS Stateful Operations messages
// (RFC 8490). DSO is the TLV-based session protocol that runs over
// connection-oriented DNS transports (TCP, DoT, DoQ); this package
// supplies the wire codec and the standard TLVs but does not bind to a
// concrete transport — callers compose it with a stream connection of
// their choice.
package dso

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// ErrInvalidDSO is returned when a DSO message or TLV cannot be encoded or
// decoded.
var ErrInvalidDSO = errors.New("dso: invalid")

// Type identifies a TLV in a DSO message (RFC 8490 §11.2).
type Type uint16

const (
	// TypeKeepAlive is the standard KeepAlive TLV (RFC 8490 §7.1).
	TypeKeepAlive Type = 1
	// TypeRetryDelay is the Retry Delay TLV (RFC 8490 §7.2).
	TypeRetryDelay Type = 2
	// TypeEncryptionPadding is the Encryption Padding TLV (RFC 8490 §7.3).
	TypeEncryptionPadding Type = 3
)

// TLV is one type-length-value entry inside a DSO message.
type TLV struct {
	typ  Type
	data []byte
}

// NewTLV constructs a TLV with the given type and data payload.
func NewTLV(t Type, data []byte) TLV {
	return TLV{typ: t, data: data}
}

// Type returns the TLV's type code.
func (t TLV) Type() Type { return t.typ }

// Data returns the TLV's payload bytes.
func (t TLV) Data() []byte { return t.data }

// Message is a parsed DSO message body. Header bookkeeping (ID, opcode = 6,
// flags) is handled by the caller — this package operates only on the
// message-data portion (RFC 8490 §5.4).
type Message struct {
	primary    TLV
	additional []TLV
}

// NewMessage constructs a DSO Message body with the given primary TLV and
// optional additional TLVs.
func NewMessage(primary TLV, additional ...TLV) Message {
	return Message{primary: primary, additional: additional}
}

// Primary returns the message's primary TLV.
func (m Message) Primary() TLV { return m.primary }

// Additional returns the additional TLVs in document order.
func (m Message) Additional() []TLV { return m.additional }

// Pack serialises m's primary and additional TLVs back-to-back. The output
// is the DNS message data portion that follows the 12-byte fixed header.
func (m *Message) Pack() ([]byte, error) {
	var buf []byte
	if m.primary.typ != 0 {
		b, err := packTLV(m.primary)
		if err != nil {
			return nil, err
		}
		buf = append(buf, b...)
	}
	for i, t := range m.additional {
		b, err := packTLV(t)
		if err != nil {
			return nil, fmt.Errorf("additional[%d]: %w", i, err)
		}
		buf = append(buf, b...)
	}
	return buf, nil
}

// Unpack parses a DSO message data portion.
func Unpack(b []byte) (*Message, error) {
	off := 0
	var primary TLV
	hasPrimary := false
	var additional []TLV
	for off < len(b) {
		t, data, n, err := unpackTLV(b[off:])
		if err != nil {
			return nil, err
		}
		off += n
		tlv := TLV{typ: t, data: data}
		if !hasPrimary {
			primary = tlv
			hasPrimary = true
			continue
		}
		additional = append(additional, tlv)
	}
	return &Message{primary: primary, additional: additional}, nil
}

func packTLV(t TLV) ([]byte, error) {
	if len(t.data) > 0xffff {
		return nil, fmt.Errorf("%w: TLV %d data length %d exceeds 65535", ErrInvalidDSO, t.typ, len(t.data))
	}
	b := make([]byte, 4+len(t.data))
	binary.BigEndian.PutUint16(b[0:], uint16(t.typ))
	binary.BigEndian.PutUint16(b[2:], uint16(len(t.data)))
	copy(b[4:], t.data)
	return b, nil
}

func unpackTLV(b []byte) (Type, []byte, int, error) {
	if len(b) < 4 {
		return 0, nil, 0, fmt.Errorf("%w: TLV header truncated", ErrInvalidDSO)
	}
	t := Type(binary.BigEndian.Uint16(b[0:]))
	l := int(binary.BigEndian.Uint16(b[2:]))
	if 4+l > len(b) {
		return 0, nil, 0, fmt.Errorf("%w: TLV data truncated (need %d, have %d)", ErrInvalidDSO, l, len(b)-4)
	}
	cp := make([]byte, l)
	copy(cp, b[4:4+l])
	return t, cp, 4 + l, nil
}

// NewKeepAlive builds a KeepAlive TLV (RFC 8490 §7.1). InactivityTimeout and
// KeepaliveInterval are encoded as 32-bit big-endian millisecond counts.
func NewKeepAlive(inactivity, keepalive time.Duration) TLV {
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:], uint32(inactivity/time.Millisecond))
	binary.BigEndian.PutUint32(data[4:], uint32(keepalive/time.Millisecond))
	return TLV{typ: TypeKeepAlive, data: data}
}

// KeepAlive decodes a KeepAlive TLV. Returns false if the TLV is not
// KeepAlive or has the wrong length.
func KeepAlive(t TLV) (inactivity, keepalive time.Duration, ok bool) {
	if t.typ != TypeKeepAlive || len(t.data) != 8 {
		return 0, 0, false
	}
	in := binary.BigEndian.Uint32(t.data[0:])
	ka := binary.BigEndian.Uint32(t.data[4:])
	return time.Duration(in) * time.Millisecond, time.Duration(ka) * time.Millisecond, true
}

// NewRetryDelay builds a Retry Delay TLV (RFC 8490 §7.2). delay is encoded
// as a 32-bit big-endian millisecond count.
func NewRetryDelay(delay time.Duration) TLV {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, uint32(delay/time.Millisecond))
	return TLV{typ: TypeRetryDelay, data: data}
}

// RetryDelay decodes a Retry Delay TLV.
func RetryDelay(t TLV) (time.Duration, bool) {
	if t.typ != TypeRetryDelay || len(t.data) != 4 {
		return 0, false
	}
	return time.Duration(binary.BigEndian.Uint32(t.data)) * time.Millisecond, true
}

// NewEncryptionPadding builds an Encryption Padding TLV (RFC 8490 §7.3).
// length zero is allowed and means "no payload".
func NewEncryptionPadding(length int) (TLV, error) {
	if length < 0 || length > 0xffff {
		return TLV{}, fmt.Errorf("%w: padding length %d out of range", ErrInvalidDSO, length)
	}
	return TLV{typ: TypeEncryptionPadding, data: make([]byte, length)}, nil
}
