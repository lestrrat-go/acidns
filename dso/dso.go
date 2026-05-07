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
	Type Type
	Data []byte
}

// Message is a parsed DSO message body. Header bookkeeping (ID, opcode = 6,
// flags) is handled by the caller — this package operates only on the
// message-data portion (RFC 8490 §5.4).
type Message struct {
	Primary    TLV   // Primary TLV (REQUIRED in requests; optional in responses)
	Additional []TLV // Additional TLVs in document order
}

// Pack serialises m's primary and additional TLVs back-to-back. The output
// is the DNS message data portion that follows the 12-byte fixed header.
func (m *Message) Pack() ([]byte, error) {
	var buf []byte
	if m.Primary.Type != 0 {
		b, err := packTLV(m.Primary)
		if err != nil {
			return nil, err
		}
		buf = append(buf, b...)
	}
	for i, t := range m.Additional {
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
		tlv := TLV{Type: t, Data: data}
		if !hasPrimary {
			primary = tlv
			hasPrimary = true
			continue
		}
		additional = append(additional, tlv)
	}
	return &Message{Primary: primary, Additional: additional}, nil
}

func packTLV(t TLV) ([]byte, error) {
	if len(t.Data) > 0xffff {
		return nil, fmt.Errorf("%w: TLV %d data length %d exceeds 65535", ErrInvalidDSO, t.Type, len(t.Data))
	}
	b := make([]byte, 4+len(t.Data))
	binary.BigEndian.PutUint16(b[0:], uint16(t.Type))
	binary.BigEndian.PutUint16(b[2:], uint16(len(t.Data)))
	copy(b[4:], t.Data)
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
	return TLV{Type: TypeKeepAlive, Data: data}
}

// KeepAlive decodes a KeepAlive TLV. Returns false if the TLV is not
// KeepAlive or has the wrong length.
func KeepAlive(t TLV) (inactivity, keepalive time.Duration, ok bool) {
	if t.Type != TypeKeepAlive || len(t.Data) != 8 {
		return 0, 0, false
	}
	in := binary.BigEndian.Uint32(t.Data[0:])
	ka := binary.BigEndian.Uint32(t.Data[4:])
	return time.Duration(in) * time.Millisecond, time.Duration(ka) * time.Millisecond, true
}

// NewRetryDelay builds a Retry Delay TLV (RFC 8490 §7.2). delay is encoded
// as a 32-bit big-endian millisecond count.
func NewRetryDelay(delay time.Duration) TLV {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, uint32(delay/time.Millisecond))
	return TLV{Type: TypeRetryDelay, Data: data}
}

// RetryDelay decodes a Retry Delay TLV.
func RetryDelay(t TLV) (time.Duration, bool) {
	if t.Type != TypeRetryDelay || len(t.Data) != 4 {
		return 0, false
	}
	return time.Duration(binary.BigEndian.Uint32(t.Data)) * time.Millisecond, true
}

// NewEncryptionPadding builds an Encryption Padding TLV (RFC 8490 §7.3).
// length zero is allowed and means "no payload".
func NewEncryptionPadding(length int) (TLV, error) {
	if length < 0 || length > 0xffff {
		return TLV{}, fmt.Errorf("%w: padding length %d out of range", ErrInvalidDSO, length)
	}
	return TLV{Type: TypeEncryptionPadding, Data: make([]byte, length)}, nil
}
