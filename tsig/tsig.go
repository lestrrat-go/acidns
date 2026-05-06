// Package tsig implements the transaction-signature mechanism of RFC 8945
// (formerly RFC 2845). It computes and verifies HMAC-based signatures
// carried in the additional section of DNS messages, primarily used for
// authenticating zone transfers (AXFR/IXFR) and dynamic updates between
// nameservers.
//
// Functions in this package operate on raw wire bytes rather than the
// dnsmsg.Message interface because TSIG signs the message AFTER its wire
// encoding (the additional count is incremented as the TSIG RR is
// appended). The intended use is:
//
//	wire, _ := dnsmsg.Marshal(m)
//	signed, _ := tsig.Sign(wire, key, time.Now(), 5*time.Minute)
//	// send signed
//
// On the receiver:
//
//	body, _, err := tsig.Verify(received, key)
//	m, _ := dnsmsg.Unmarshal(body)
package tsig

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // legacy hmac-sha1. still in active use.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"time"

	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsname"
)

// Algorithm names the HMAC variant (canonical form per RFC 8945 §6).
type Algorithm string

const (
	HMACSHA1   Algorithm = "hmac-sha1."
	HMACSHA256 Algorithm = "hmac-sha256."
	HMACSHA384 Algorithm = "hmac-sha384."
	HMACSHA512 Algorithm = "hmac-sha512."
)

// Key holds the credentials shared with the peer.
type Key struct {
	Name      dnsname.Name
	Algorithm Algorithm
	Secret    []byte
}

// ErrTSIGMissing is returned by Verify when the message has no TSIG RR.
var ErrTSIGMissing = errors.New("tsig: no TSIG record in message")

// ErrBadTime is returned when the signed timestamp is outside fudge.
var ErrBadTime = errors.New("tsig: time outside fudge window")

// ErrBadSignature is returned when the HMAC fails to verify.
var ErrBadSignature = errors.New("tsig: bad signature")

const (
	tsigType  uint16 = 250
	tsigClass uint16 = 255 // ANY
)

// SignMessage marshals m and returns the TSIG-signed wire-format bytes.
// Equivalent to Sign(dnsmsg.Marshal(m), key, now, fudge) — provided so
// callers don't have to think about the marshal/sign ordering. Works for
// any DNS message: queries, updates, NOTIFY, anything.
//
// fudge is the clock-skew window the receiver tolerates. Five minutes is
// conventional.
func SignMessage(m dnsmsg.Message, key Key, now time.Time, fudge time.Duration) ([]byte, error) {
	wire, err := dnsmsg.Marshal(m)
	if err != nil {
		return nil, err
	}
	return Sign(wire, key, now, fudge)
}

// Sign appends a TSIG RR to the additional section of wire and returns
// the new wire bytes.
func Sign(wire []byte, key Key, now time.Time, fudge time.Duration) ([]byte, error) {
	if len(wire) < 12 {
		return nil, fmt.Errorf("tsig: wire too short")
	}
	algName := dnsname.MustParse(string(key.Algorithm))

	timeSigned := uint64(now.Unix())
	fudgeSecs := uint16(fudge.Seconds())

	tsigVars := buildTSIGVars(key.Name, algName, timeSigned, fudgeSecs, 0, nil)
	mac, err := computeHMAC(key, append(append([]byte(nil), wire...), tsigVars...))
	if err != nil {
		return nil, err
	}

	origID := binary.BigEndian.Uint16(wire[0:2])

	rdata := buildTSIGRData(algName, timeSigned, fudgeSecs, mac, origID, 0, nil)
	out := append([]byte(nil), wire...)
	out = appendTSIGRR(out, key.Name, rdata)

	// Increment ARCOUNT.
	arcount := binary.BigEndian.Uint16(out[10:12])
	binary.BigEndian.PutUint16(out[10:12], arcount+1)
	return out, nil
}

// Verify confirms the trailing TSIG RR over wire using key. Returns the
// message body without the TSIG RR (with ARCOUNT decremented and the
// original message ID restored if it was rewritten) and the time at which
// the signature was generated.
func Verify(wire []byte, key Key, now time.Time, fudge time.Duration) ([]byte, time.Time, error) {
	body, tsig, err := stripTSIG(wire)
	if err != nil {
		return nil, time.Time{}, err
	}
	if !tsig.keyName.Equal(key.Name) {
		return nil, time.Time{}, fmt.Errorf("tsig: key name mismatch")
	}
	if !tsig.algorithm.Equal(dnsname.MustParse(string(key.Algorithm))) {
		return nil, time.Time{}, fmt.Errorf("tsig: algorithm mismatch")
	}
	signed := time.Unix(int64(tsig.timeSigned), 0).UTC()
	if delta := now.Sub(signed); delta > fudge || delta < -fudge {
		return nil, signed, fmt.Errorf("%w: delta %s outside fudge %s", ErrBadTime, delta, fudge)
	}

	// Restore the original ID before recomputing the MAC.
	bodyForMAC := append([]byte(nil), body...)
	binary.BigEndian.PutUint16(bodyForMAC[0:2], tsig.origID)

	tsigVars := buildTSIGVars(tsig.keyName, tsig.algorithm, tsig.timeSigned, tsig.fudge, tsig.errCode, tsig.other)
	mac, err := computeHMAC(key, append(bodyForMAC, tsigVars...))
	if err != nil {
		return nil, signed, err
	}
	if !hmac.Equal(mac, tsig.mac) {
		return nil, signed, ErrBadSignature
	}
	return bodyForMAC, signed, nil
}

// computeHMAC returns the HMAC of payload under key.
func computeHMAC(key Key, payload []byte) ([]byte, error) {
	var h hash.Hash
	switch key.Algorithm {
	case HMACSHA1:
		h = hmac.New(sha1.New, key.Secret)
	case HMACSHA256:
		h = hmac.New(sha256.New, key.Secret)
	case HMACSHA384:
		h = hmac.New(sha512.New384, key.Secret)
	case HMACSHA512:
		h = hmac.New(sha512.New, key.Secret)
	default:
		return nil, fmt.Errorf("tsig: unsupported algorithm %q", key.Algorithm)
	}
	h.Write(payload)
	return h.Sum(nil), nil
}

// buildTSIGVars builds the canonical "TSIG variables" prefix used in the
// HMAC computation per RFC 8945 §4.3.3.
func buildTSIGVars(keyName, algName dnsname.Name, timeSigned uint64, fudge, errCode uint16, other []byte) []byte {
	var buf []byte
	buf = append(buf, keyName.AppendWire(nil)...)
	buf = binary.BigEndian.AppendUint16(buf, tsigClass)
	buf = binary.BigEndian.AppendUint32(buf, 0) // TTL = 0
	buf = append(buf, algName.AppendWire(nil)...)
	buf = appendUint48(buf, timeSigned)
	buf = binary.BigEndian.AppendUint16(buf, fudge)
	buf = binary.BigEndian.AppendUint16(buf, errCode)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(other)))
	buf = append(buf, other...)
	return buf
}

// buildTSIGRData builds the wire-format RDATA of the TSIG RR.
func buildTSIGRData(algName dnsname.Name, timeSigned uint64, fudge uint16, mac []byte, origID, errCode uint16, other []byte) []byte {
	var buf []byte
	buf = append(buf, algName.AppendWire(nil)...)
	buf = appendUint48(buf, timeSigned)
	buf = binary.BigEndian.AppendUint16(buf, fudge)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(mac)))
	buf = append(buf, mac...)
	buf = binary.BigEndian.AppendUint16(buf, origID)
	buf = binary.BigEndian.AppendUint16(buf, errCode)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(other)))
	buf = append(buf, other...)
	return buf
}

func appendTSIGRR(wire []byte, owner dnsname.Name, rd []byte) []byte {
	out := append(wire, owner.AppendWire(nil)...)
	out = binary.BigEndian.AppendUint16(out, tsigType)
	out = binary.BigEndian.AppendUint16(out, tsigClass)
	out = binary.BigEndian.AppendUint32(out, 0) // TTL
	out = binary.BigEndian.AppendUint16(out, uint16(len(rd)))
	out = append(out, rd...)
	return out
}

func appendUint48(buf []byte, v uint64) []byte {
	return append(buf,
		byte(v>>40), byte(v>>32), byte(v>>24),
		byte(v>>16), byte(v>>8), byte(v))
}

type parsedTSIG struct {
	keyName    dnsname.Name
	algorithm  dnsname.Name
	timeSigned uint64
	fudge      uint16
	mac        []byte
	origID     uint16
	errCode    uint16
	other      []byte
}

// stripTSIG locates the trailing TSIG RR in wire (it MUST be the last RR
// per RFC 8945 §5.1), parses it, and returns the body without the TSIG
// (with ARCOUNT decremented by 1) plus the parsed TSIG.
func stripTSIG(wire []byte) ([]byte, parsedTSIG, error) {
	if len(wire) < 12 {
		return nil, parsedTSIG{}, fmt.Errorf("tsig: wire too short")
	}
	arcount := binary.BigEndian.Uint16(wire[10:12])
	if arcount == 0 {
		return nil, parsedTSIG{}, ErrTSIGMissing
	}

	// The TSIG RR is the last RR in the message. We scan from the start to
	// find every RR boundary, returning the offset of the last one.
	start, err := findLastRROffset(wire)
	if err != nil {
		return nil, parsedTSIG{}, err
	}

	keyName, off, err := dnsname.DecodeWire(wire, start)
	if err != nil {
		return nil, parsedTSIG{}, fmt.Errorf("tsig: parse owner: %w", err)
	}
	if off+10 > len(wire) {
		return nil, parsedTSIG{}, fmt.Errorf("tsig: truncated header")
	}
	rrType := binary.BigEndian.Uint16(wire[off : off+2])
	if rrType != tsigType {
		return nil, parsedTSIG{}, ErrTSIGMissing
	}
	rdlen := int(binary.BigEndian.Uint16(wire[off+8 : off+10]))
	rdataStart := off + 10
	rdataEnd := rdataStart + rdlen
	if rdataEnd > len(wire) {
		return nil, parsedTSIG{}, fmt.Errorf("tsig: truncated rdata")
	}

	tsig, err := parseTSIGRData(wire, rdataStart, rdataEnd)
	if err != nil {
		return nil, parsedTSIG{}, err
	}
	tsig.keyName = keyName

	// Build the body without the TSIG RR and with ARCOUNT decremented.
	body := append([]byte(nil), wire[:start]...)
	binary.BigEndian.PutUint16(body[10:12], arcount-1)
	return body, tsig, nil
}

func parseTSIGRData(wire []byte, start, end int) (parsedTSIG, error) {
	algName, off, err := dnsname.DecodeWire(wire, start)
	if err != nil {
		return parsedTSIG{}, fmt.Errorf("tsig: parse alg: %w", err)
	}
	need := 6 + 2 + 2 + 2 + 2 + 2 // time + fudge + macSize + (mac after) + origID + err + otherLen
	if off+6+2+2 > end {
		return parsedTSIG{}, fmt.Errorf("tsig: truncated time/fudge/mac-size")
	}
	timeSigned := readUint48(wire[off : off+6])
	off += 6
	fudge := binary.BigEndian.Uint16(wire[off : off+2])
	off += 2
	macSize := int(binary.BigEndian.Uint16(wire[off : off+2]))
	off += 2
	if off+macSize+2+2+2 > end {
		return parsedTSIG{}, fmt.Errorf("tsig: truncated mac/origID/err/otherLen")
	}
	mac := append([]byte(nil), wire[off:off+macSize]...)
	off += macSize
	origID := binary.BigEndian.Uint16(wire[off : off+2])
	off += 2
	errCode := binary.BigEndian.Uint16(wire[off : off+2])
	off += 2
	otherLen := int(binary.BigEndian.Uint16(wire[off : off+2]))
	off += 2
	if off+otherLen > end {
		return parsedTSIG{}, fmt.Errorf("tsig: truncated other-data")
	}
	other := append([]byte(nil), wire[off:off+otherLen]...)
	_ = need
	return parsedTSIG{
		algorithm:  algName,
		timeSigned: timeSigned,
		fudge:      fudge,
		mac:        mac,
		origID:     origID,
		errCode:    errCode,
		other:      other,
	}, nil
}

func readUint48(b []byte) uint64 {
	return uint64(b[0])<<40 | uint64(b[1])<<32 | uint64(b[2])<<24 |
		uint64(b[3])<<16 | uint64(b[4])<<8 | uint64(b[5])
}

// findLastRROffset returns the start offset of the last RR in wire by
// walking the question and RR sections. It is intentionally a fresh
// minimal walker rather than a re-parse via dnsmsg.Unmarshal — TSIG must
// run on the exact wire bytes the peer produced, with no canonicalisation.
func findLastRROffset(wire []byte) (int, error) {
	qdcount := int(binary.BigEndian.Uint16(wire[4:6]))
	ancount := int(binary.BigEndian.Uint16(wire[6:8]))
	nscount := int(binary.BigEndian.Uint16(wire[8:10]))
	arcount := int(binary.BigEndian.Uint16(wire[10:12]))
	totalRR := ancount + nscount + arcount
	off := 12

	// Skip questions.
	for i := 0; i < qdcount; i++ {
		_, next, err := dnsname.DecodeWire(wire, off)
		if err != nil {
			return 0, err
		}
		off = next + 4 // qtype + qclass
		if off > len(wire) {
			return 0, fmt.Errorf("tsig: truncated question")
		}
	}

	last := off
	for i := 0; i < totalRR; i++ {
		last = off
		_, next, err := dnsname.DecodeWire(wire, off)
		if err != nil {
			return 0, err
		}
		if next+10 > len(wire) {
			return 0, fmt.Errorf("tsig: truncated rr header")
		}
		rdlen := int(binary.BigEndian.Uint16(wire[next+8 : next+10]))
		off = next + 10 + rdlen
		if off > len(wire) {
			return 0, fmt.Errorf("tsig: truncated rr body")
		}
	}
	return last, nil
}
