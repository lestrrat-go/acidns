// Package tsig implements the transaction-signature mechanism of RFC 8945
// (formerly RFC 2845). It computes and verifies HMAC-based signatures
// carried in the additional section of DNS messages, primarily used for
// authenticating zone transfers (AXFR/IXFR) and dynamic updates between
// nameservers.
//
// Functions in this package operate on raw msg bytes rather than the
// wire.Message interface because TSIG signs the message AFTER its msg
// encoding (the additional count is incremented as the TSIG RR is
// appended). The intended use is:
//
//	msg, _ := wire.Marshal(m)
//	signed, _ := tsig.Sign(msg, key, time.Now(), 5*time.Minute)
//	// send signed
//
// On the receiver:
//
//	body, _, err := tsig.Verify(received, key)
//	m, _ := wire.Unmarshal(body)
//
// # Replay protection
//
// Verify enforces the RFC 8945 §5.2.3 fudge-window time check: a
// signed message whose timestamp is more than fudge seconds away
// from the verifier's clock is rejected as BADTIME. That bounds the
// window in which a captured-and-replayed message can be valid, but
// does NOT prevent replay within the fudge window. RFC 8945 leaves
// stronger replay protection (a (key, time, MAC)-tuple cache,
// monotonic-counter validation, etc.) to the caller because the
// right policy depends on the message semantics: a re-signed AXFR
// answer is harmless to replay, but a re-played dynamic UPDATE can
// re-execute a no-longer-intended mutation.
//
// Callers handling UPDATE or other side-effecting opcodes that
// arrive over TSIG-protected channels MUST add their own replay
// defence — typically a bounded LRU of recently-seen MACs scoped to
// the fudge window. This package deliberately stays a stateless
// verifier so it can be used in both authoritative and middleware
// roles without coupling to a particular cache implementation.
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

	"github.com/lestrrat-go/acidns/wire"
)

// Algorithm names the HMAC variant (canonical form per RFC 8945 §6).
type Algorithm string

const (
	HMACSHA1   Algorithm = "hmac-sha1."
	HMACSHA256 Algorithm = "hmac-sha256."
	HMACSHA384 Algorithm = "hmac-sha384."
	HMACSHA512 Algorithm = "hmac-sha512."
)

// Key holds the credentials shared with the peer. The fields are
// unexported so callers cannot mutate the secret bytes after the Key
// is built — a mutation would silently invalidate every signature
// produced or verified afterwards. Construct via [NewKey], which
// snapshots the secret on input. The zero value is unusable; pass a
// constructed Key by value freely (it carries only a small slice
// header and two short slices).
type Key struct {
	name      wire.Name
	algorithm Algorithm
	secret    []byte
}

// NewKey returns a Key with the supplied identity material. The
// secret slice is copied so a later mutation of the caller's slice
// does not leak into TSIG signing/verification.
func NewKey(name wire.Name, alg Algorithm, secret []byte) Key {
	s := make([]byte, len(secret))
	copy(s, secret)
	return Key{name: name, algorithm: alg, secret: s}
}

// Name returns the key name (the DNS name used as the TSIG owner).
func (k Key) Name() wire.Name { return k.name }

// Algorithm returns the HMAC algorithm associated with the key.
func (k Key) Algorithm() Algorithm { return k.algorithm }

// ErrTSIGMissing is returned by Verify when the message has no TSIG RR.
var ErrTSIGMissing = errors.New("tsig: no TSIG record in message")

// ErrBadTime is returned when the signed timestamp is outside fudge.
var ErrBadTime = errors.New("tsig: time outside fudge window")

// ErrBadSignature is returned when the HMAC fails to verify.
var ErrBadSignature = errors.New("tsig: bad signature")

// ErrBadTruncation is returned when a received MAC is shorter than RFC
// 8945 §5.2.2.1 permits — i.e. less than 10 octets or less than half the
// algorithm's full output length, whichever is greater.
var ErrBadTruncation = errors.New("tsig: MAC shorter than allowed")

// ErrUnsupportedAlgorithm is returned when a TSIG operation is asked
// to sign or verify under an algorithm this package does not implement.
// Treating unknown algorithms as fail-closed prevents a peer from
// passing verification with a generic short-MAC floor against an
// algorithm the verifier cannot actually compute.
var ErrUnsupportedAlgorithm = errors.New("tsig: unsupported algorithm")

const (
	tsigType  uint16 = 250
	tsigClass uint16 = 255 // ANY
)

// SignMessage marshals m and returns the TSIG-signed msg-format bytes.
// Equivalent to Sign(wire.Marshal(m), key, now, fudge) — provided so
// callers don't have to think about the marshal/sign ordering. Works for
// any DNS message: queries, updates, NOTIFY, anything.
//
// fudge is the clock-skew window the receiver tolerates. Five minutes is
// conventional.
func SignMessage(m wire.Message, key Key, now time.Time, fudge time.Duration) ([]byte, error) {
	msg, err := wire.Marshal(m)
	if err != nil {
		return nil, err
	}
	return Sign(msg, key, now, fudge)
}

// Sign appends a TSIG RR to the additional section of msg and returns
// the new msg bytes.
//
// Sign is for queries and other un-paired messages. To sign a response
// to a TSIG-signed query, use [SignResponse] (which binds the response
// signature to the request MAC per RFC 8945 §5.3.1). For envelopes
// after the first in a multi-message AXFR, use [SignAXFRChunk] which
// chains MACs per §5.3.2.
func Sign(msg []byte, key Key, now time.Time, fudge time.Duration) ([]byte, error) {
	out, _, err := signWithPrefix(msg, key, nil, false, now, fudge)
	return out, err
}

// SignResponse appends a TSIG RR to msg, binding the signature to the
// MAC of the request that triggered this response (RFC 8945 §5.3.1).
// requestMAC is the MAC bytes returned from [Verify] of the request.
//
// This is what an authoritative or recursive server should use when
// answering a TSIG-signed query: it prevents the response from being
// replayed against a different request.
func SignResponse(msg []byte, key Key, requestMAC []byte, now time.Time, fudge time.Duration) ([]byte, error) {
	if len(requestMAC) == 0 {
		return nil, fmt.Errorf("tsig: SignResponse requires requestMAC")
	}
	out, _, err := signWithPrefix(msg, key, requestMAC, false, now, fudge)
	return out, err
}

// SignAXFRChunk signs an envelope after the first in a multi-message
// AXFR/IXFR response (RFC 8945 §5.3.2). priorMAC is the MAC produced
// by the previous signed envelope (returned via the second result of
// SignAXFRChunk, or via [Verify] of the request for the first
// envelope; the first envelope itself is signed with [SignResponse]).
//
// Per §5.3.2 the signing input is constructed with priorMAC as a
// length-prefixed prefix and uses only the "TSIG timers" portion
// (time_signed + fudge) of the variables. The new MAC returned must be
// passed as priorMAC to the next call.
func SignAXFRChunk(msg []byte, key Key, priorMAC []byte, now time.Time, fudge time.Duration) ([]byte, []byte, error) {
	if len(priorMAC) == 0 {
		return nil, nil, fmt.Errorf("tsig: SignAXFRChunk requires priorMAC")
	}
	return signWithPrefix(msg, key, priorMAC, true, now, fudge)
}

// signWithPrefix is the common signer. priorMAC, when non-nil, is
// length-prefixed and prepended to the HMAC input (RFC 8945 §5.3.1 and
// §5.3.2). When timersOnly is true, only time_signed+fudge are used as
// the variables (§5.3.2), otherwise the full TSIG vars are used.
func signWithPrefix(msg []byte, key Key, priorMAC []byte, timersOnly bool, now time.Time, fudge time.Duration) ([]byte, []byte, error) {
	if len(msg) < 12 {
		return nil, nil, fmt.Errorf("tsig: msg too short")
	}
	algName := wire.MustParseName(string(key.algorithm))

	timeSigned := uint64(now.Unix())
	fudgeSecs := uint16(fudge.Seconds())

	input := buildSigningInput(msg, key.name, algName, priorMAC, timeSigned, fudgeSecs, 0, nil, timersOnly)
	mac, err := computeHMAC(key, input)
	if err != nil {
		return nil, nil, err
	}

	origID := binary.BigEndian.Uint16(msg[0:2])
	rdata := buildTSIGRData(algName, timeSigned, fudgeSecs, mac, origID, 0, nil)
	out := append([]byte(nil), msg...)
	out = appendTSIGRR(out, key.name, rdata)

	arcount := binary.BigEndian.Uint16(out[10:12])
	binary.BigEndian.PutUint16(out[10:12], arcount+1)
	return out, mac, nil
}

// buildSigningInput assembles the byte stream over which the HMAC is
// computed. See RFC 8945 §4.3 (request), §5.3.1 (response prefixes
// requestMAC), §5.3.2 (chained AXFR uses prior MAC + timers-only).
func buildSigningInput(msg []byte, keyName, algName wire.Name, priorMAC []byte,
	timeSigned uint64, fudge, errCode uint16, other []byte, timersOnly bool,
) []byte {
	var input []byte
	if priorMAC != nil {
		input = binary.BigEndian.AppendUint16(input, uint16(len(priorMAC)))
		input = append(input, priorMAC...)
	}
	input = append(input, msg...)
	if timersOnly {
		input = appendUint48(input, timeSigned)
		input = binary.BigEndian.AppendUint16(input, fudge)
		return input
	}
	return append(input, buildTSIGVars(keyName, algName, timeSigned, fudge, errCode, other)...)
}

// Verify confirms the trailing TSIG RR over msg using key. Returns the
// message body without the TSIG RR (with ARCOUNT decremented and the
// original message ID restored if it was rewritten) and the time at which
// the signature was generated.
//
// Verify is for un-paired messages — typically a server verifying a
// signed query. The MAC bytes (the TSIG signature) can be retrieved
// via [VerifyMAC] if the caller intends to bind a response to this
// request via [SignResponse].
func Verify(msg []byte, key Key, now time.Time, fudge time.Duration) ([]byte, time.Time, error) {
	body, _, signed, err := verifyWithPrefix(msg, key, nil, false, now, fudge)
	return body, signed, err
}

// VerifyMAC is like [Verify] but also returns the MAC bytes from the
// request's TSIG, so the caller can sign its response with
// [SignResponse] (RFC 8945 §5.3.1).
func VerifyMAC(msg []byte, key Key, now time.Time, fudge time.Duration) ([]byte, []byte, time.Time, error) {
	return verifyWithPrefix(msg, key, nil, false, now, fudge)
}

// VerifyResponse confirms a response signature that binds itself to the
// request MAC (RFC 8945 §5.3.1). requestMAC is the value returned from
// [VerifyMAC] of the original request on the server side, or remembered
// by the client after it called [Sign]. Returns the body, the response
// MAC (use as priorMAC of the first [VerifyAXFRChunk] call when reading
// a chained AXFR), and the signing time.
func VerifyResponse(msg []byte, key Key, requestMAC []byte, now time.Time, fudge time.Duration) ([]byte, []byte, time.Time, error) {
	if len(requestMAC) == 0 {
		return nil, nil, time.Time{}, fmt.Errorf("tsig: VerifyResponse requires requestMAC")
	}
	return verifyWithPrefix(msg, key, requestMAC, false, now, fudge)
}

// VerifyAXFRChunk verifies a non-first envelope in a chained AXFR
// (RFC 8945 §5.3.2). Returns the body (TSIG stripped if present), the
// MAC of this envelope (use as priorMAC for the next chunk), and the
// time of signing. If the envelope is unsigned (intermediate envelopes
// MAY be unsigned per §5.3.2), the returned MAC is nil and ErrTSIGMissing
// is returned along with the unmodified body.
func VerifyAXFRChunk(msg []byte, key Key, priorMAC []byte, now time.Time, fudge time.Duration) ([]byte, []byte, time.Time, error) {
	if len(priorMAC) == 0 {
		return nil, nil, time.Time{}, fmt.Errorf("tsig: VerifyAXFRChunk requires priorMAC")
	}
	return verifyWithPrefix(msg, key, priorMAC, true, now, fudge)
}

// verifyWithPrefix is the common verifier. See [signWithPrefix] for
// how priorMAC and timersOnly drive the HMAC input shape.
func verifyWithPrefix(msg []byte, key Key, priorMAC []byte, timersOnly bool, now time.Time, fudge time.Duration) ([]byte, []byte, time.Time, error) {
	body, tsig, err := stripTSIG(msg)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	if !tsig.keyName.Equal(key.name) {
		return nil, nil, time.Time{}, fmt.Errorf("tsig: key name mismatch")
	}
	if !tsig.algorithm.Equal(wire.MustParseName(string(key.algorithm))) {
		return nil, nil, time.Time{}, fmt.Errorf("tsig: algorithm mismatch")
	}
	floor, ok := minMACSize(key.algorithm)
	if !ok {
		// Refuse unknown algorithms outright. Allowing them through to
		// the prefix-MAC compare with a generic 10-byte floor would let
		// a peer that lies about the algorithm pass with a 10-byte tag
		// matched against an HMAC the verifier cannot actually produce.
		return nil, nil, time.Time{}, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, key.algorithm)
	}
	if len(tsig.mac) < floor {
		return nil, nil, time.Time{}, fmt.Errorf("%w: got %d bytes, need at least %d for %s",
			ErrBadTruncation, len(tsig.mac), floor, key.algorithm)
	}
	signed := time.Unix(int64(tsig.timeSigned), 0).UTC()

	bodyForMAC := append([]byte(nil), body...)
	binary.BigEndian.PutUint16(bodyForMAC[0:2], tsig.origID)

	input := buildSigningInput(bodyForMAC, tsig.keyName, tsig.algorithm, priorMAC,
		tsig.timeSigned, tsig.fudge, tsig.errCode, tsig.other, timersOnly)
	mac, err := computeHMAC(key, input)
	if err != nil {
		return nil, nil, signed, err
	}
	// RFC 8945 §5.2.2.1 permits the peer to send a MAC truncated to the
	// per-algorithm floor. Compare against a matching prefix of the
	// recomputed MAC so a spec-conformant truncated signature still
	// verifies; the prior length check already rejected anything shorter
	// than the floor.
	if len(tsig.mac) > len(mac) {
		return nil, nil, signed, fmt.Errorf("tsig: received MAC longer than %s output", key.algorithm)
	}
	if !hmac.Equal(mac[:len(tsig.mac)], tsig.mac) {
		return nil, nil, signed, ErrBadSignature
	}
	// MAC verified — only now is timeSigned authenticated, so the
	// time-window check can be trusted. Order MAC-then-time also denies
	// an unauthenticated peer a BADTIME timing oracle on the verifier's
	// clock skew.
	if delta := now.Sub(signed); delta > fudge || delta < -fudge {
		return nil, nil, signed, fmt.Errorf("%w: delta %s outside fudge %s", ErrBadTime, delta, fudge)
	}
	return bodyForMAC, tsig.mac, signed, nil
}

// minMACSize returns the per-algorithm minimum MAC length per RFC 8945
// §5.2.2.1 ("The truncated MAC SHALL NOT be less than 10 octets and at
// least half of the length of the full MAC") and whether the algorithm
// is known. Unknown algorithms return ok=false; callers MUST treat
// that as fail-closed — a generic 10-byte floor here would let a peer
// who advertises an unsupported algorithm pass verification with a
// 10-byte tag that cannot be reproduced from any key the verifier
// actually holds.
func minMACSize(alg Algorithm) (int, bool) {
	switch alg {
	case HMACSHA1:
		return 10, true // sha1=20, half=10
	case HMACSHA256:
		return 16, true
	case HMACSHA384:
		return 24, true
	case HMACSHA512:
		return 32, true
	default:
		return 0, false
	}
}

// computeHMAC returns the HMAC of payload under key.
func computeHMAC(key Key, payload []byte) ([]byte, error) {
	var h hash.Hash
	switch key.algorithm {
	case HMACSHA1:
		h = hmac.New(sha1.New, key.secret)
	case HMACSHA256:
		h = hmac.New(sha256.New, key.secret)
	case HMACSHA384:
		h = hmac.New(sha512.New384, key.secret)
	case HMACSHA512:
		h = hmac.New(sha512.New, key.secret)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, key.algorithm)
	}
	h.Write(payload)
	return h.Sum(nil), nil
}

// buildTSIGVars builds the canonical "TSIG variables" prefix used in the
// HMAC computation per RFC 8945 §4.3.3.
func buildTSIGVars(keyName, algName wire.Name, timeSigned uint64, fudge, errCode uint16, other []byte) []byte {
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

// buildTSIGRData builds the msg-format RDATA of the TSIG RR.
func buildTSIGRData(algName wire.Name, timeSigned uint64, fudge uint16, mac []byte, origID, errCode uint16, other []byte) []byte {
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

func appendTSIGRR(msg []byte, owner wire.Name, rd []byte) []byte {
	out := append(msg, owner.AppendWire(nil)...)
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
	keyName    wire.Name
	algorithm  wire.Name
	timeSigned uint64
	fudge      uint16
	mac        []byte
	origID     uint16
	errCode    uint16
	other      []byte
}

// stripTSIG locates the trailing TSIG RR in msg (it MUST be the last RR
// per RFC 8945 §5.1), parses it, and returns the body without the TSIG
// (with ARCOUNT decremented by 1) plus the parsed TSIG.
func stripTSIG(msg []byte) ([]byte, parsedTSIG, error) {
	if len(msg) < 12 {
		return nil, parsedTSIG{}, fmt.Errorf("tsig: msg too short")
	}
	arcount := binary.BigEndian.Uint16(msg[10:12])
	if arcount == 0 {
		return nil, parsedTSIG{}, ErrTSIGMissing
	}

	// The TSIG RR is the last RR in the message. We scan from the start to
	// find every RR boundary, returning the offset of the last one.
	start, err := findLastRROffset(msg)
	if err != nil {
		return nil, parsedTSIG{}, err
	}

	keyName, off, err := wire.DecodeName(msg, start)
	if err != nil {
		return nil, parsedTSIG{}, fmt.Errorf("tsig: parse owner: %w", err)
	}
	if off+10 > len(msg) {
		return nil, parsedTSIG{}, fmt.Errorf("tsig: truncated header")
	}
	rrType := binary.BigEndian.Uint16(msg[off : off+2])
	if rrType != tsigType {
		return nil, parsedTSIG{}, ErrTSIGMissing
	}
	rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
	rdataStart := off + 10
	rdataEnd := rdataStart + rdlen
	if rdataEnd > len(msg) {
		return nil, parsedTSIG{}, fmt.Errorf("tsig: truncated rdata")
	}

	tsig, err := parseTSIGRData(msg, rdataStart, rdataEnd)
	if err != nil {
		return nil, parsedTSIG{}, err
	}
	tsig.keyName = keyName

	// Build the body without the TSIG RR and with ARCOUNT decremented.
	body := append([]byte(nil), msg[:start]...)
	binary.BigEndian.PutUint16(body[10:12], arcount-1)
	return body, tsig, nil
}

func parseTSIGRData(msg []byte, start, end int) (parsedTSIG, error) {
	algName, off, err := wire.DecodeName(msg, start)
	if err != nil {
		return parsedTSIG{}, fmt.Errorf("tsig: parse alg: %w", err)
	}
	if off+6+2+2 > end {
		return parsedTSIG{}, fmt.Errorf("tsig: truncated time/fudge/mac-size")
	}
	timeSigned := readUint48(msg[off : off+6])
	off += 6
	fudge := binary.BigEndian.Uint16(msg[off : off+2])
	off += 2
	macSize := int(binary.BigEndian.Uint16(msg[off : off+2]))
	off += 2
	if off+macSize+2+2+2 > end {
		return parsedTSIG{}, fmt.Errorf("tsig: truncated mac/origID/err/otherLen")
	}
	mac := append([]byte(nil), msg[off:off+macSize]...)
	off += macSize
	origID := binary.BigEndian.Uint16(msg[off : off+2])
	off += 2
	errCode := binary.BigEndian.Uint16(msg[off : off+2])
	off += 2
	otherLen := int(binary.BigEndian.Uint16(msg[off : off+2]))
	off += 2
	if off+otherLen > end {
		return parsedTSIG{}, fmt.Errorf("tsig: truncated other-data")
	}
	other := append([]byte(nil), msg[off:off+otherLen]...)
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

// findLastRROffset returns the start offset of the last RR in msg by
// walking the question and RR sections. It is intentionally a fresh
// minimal walker rather than a re-parse via wire.Unmarshal — TSIG must
// run on the exact msg bytes the peer produced, with no canonicalisation.
func findLastRROffset(msg []byte) (int, error) {
	qdcount := int(binary.BigEndian.Uint16(msg[4:6]))
	ancount := int(binary.BigEndian.Uint16(msg[6:8]))
	nscount := int(binary.BigEndian.Uint16(msg[8:10]))
	arcount := int(binary.BigEndian.Uint16(msg[10:12]))
	totalRR := ancount + nscount + arcount
	off := 12

	// Skip questions.
	for range qdcount {
		_, next, err := wire.DecodeName(msg, off)
		if err != nil {
			return 0, err
		}
		off = next + 4 // qtype + qclass
		if off > len(msg) {
			return 0, fmt.Errorf("tsig: truncated question")
		}
	}

	last := off
	for range totalRR {
		last = off
		_, next, err := wire.DecodeName(msg, off)
		if err != nil {
			return 0, err
		}
		if next+10 > len(msg) {
			return 0, fmt.Errorf("tsig: truncated rr header")
		}
		rdlen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
		off = next + 10 + rdlen
		if off > len(msg) {
			return 0, fmt.Errorf("tsig: truncated rr body")
		}
	}
	return last, nil
}
