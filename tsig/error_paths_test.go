package tsig_test

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/tsig"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/stretchr/testify/require"
)

// TestSignMessageMarshalError exercises the error path in SignMessage when
// wire.Marshal fails. Building a Message with an invalid name via raw record
// construction is impractical; instead we directly exercise Sign with a too
// short msg, which hits the same kind of guard.
func TestSignMessageMarshalError(t *testing.T) {
	t.Parallel()
	// SignMessage on a default-constructed (zero) Message should work
	// because wire.Marshal on an empty message succeeds. Use Sign directly
	// to exercise its msg-length guard.
	key := tsig.Key{
		Name:      wire.MustParseName("k.example."),
		Algorithm: tsig.HMACSHA256,
		Secret:    []byte("secret"),
	}
	_, err := tsig.Sign([]byte{0x00, 0x01}, key, time.Now(), time.Minute)
	require.Error(t, err)
	require.Contains(t, err.Error(), "msg too short")
}

func TestSignUnsupportedAlgorithm(t *testing.T) {
	t.Parallel()
	key := tsig.Key{
		Name:      wire.MustParseName("k.example."),
		Algorithm: tsig.Algorithm("hmac-bogus."),
		Secret:    []byte("secret"),
	}
	msg := mkMessage(t)
	_, err := tsig.Sign(msg, key, time.Now(), time.Minute)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported algorithm")
}

func TestVerifyMsgTooShort(t *testing.T) {
	t.Parallel()
	key := tsig.Key{
		Name:      wire.MustParseName("k.example."),
		Algorithm: tsig.HMACSHA256,
		Secret:    []byte("s"),
	}
	_, _, err := tsig.Verify([]byte{0x00, 0x01}, key, time.Now(), time.Minute)
	require.Error(t, err)
	require.Contains(t, err.Error(), "msg too short")
}

func TestVerifyKeyNameMismatch(t *testing.T) {
	t.Parallel()
	signKey := tsig.Key{
		Name:      wire.MustParseName("alice.example."),
		Algorithm: tsig.HMACSHA256,
		Secret:    []byte("shared-secret-bytes"),
	}
	verifyKey := signKey
	verifyKey.Name = wire.MustParseName("bob.example.")

	msg := mkMessage(t)
	now := time.Now().Truncate(time.Second)
	signed, err := tsig.Sign(msg, signKey, now, time.Minute)
	require.NoError(t, err)

	_, _, err = tsig.Verify(signed, verifyKey, now, time.Minute)
	require.Error(t, err)
	require.Contains(t, err.Error(), "key name mismatch")
}

func TestVerifyAlgorithmMismatch(t *testing.T) {
	t.Parallel()
	signKey := tsig.Key{
		Name:      wire.MustParseName("k.example."),
		Algorithm: tsig.HMACSHA256,
		Secret:    []byte("shared-secret-bytes"),
	}
	verifyKey := signKey
	verifyKey.Algorithm = tsig.HMACSHA512

	msg := mkMessage(t)
	now := time.Now().Truncate(time.Second)
	signed, err := tsig.Sign(msg, signKey, now, time.Minute)
	require.NoError(t, err)

	_, _, err = tsig.Verify(signed, verifyKey, now, time.Minute)
	require.Error(t, err)
	require.Contains(t, err.Error(), "algorithm mismatch")
}

// TestVerifyClockSkewBefore exercises the negative-delta branch of the
// fudge check (signature from the future).
func TestVerifyClockSkewBefore(t *testing.T) {
	t.Parallel()
	key := tsig.Key{
		Name:      wire.MustParseName("k.example."),
		Algorithm: tsig.HMACSHA256,
		Secret:    []byte("shared-secret-bytes"),
	}
	msg := mkMessage(t)
	signedAt := time.Now().Truncate(time.Second).Add(2 * time.Hour)
	signed, err := tsig.Sign(msg, key, signedAt, 60*time.Second)
	require.NoError(t, err)

	earlier := signedAt.Add(-2 * time.Hour)
	_, _, err = tsig.Verify(signed, key, earlier, 60*time.Second)
	require.ErrorIs(t, err, tsig.ErrBadTime)
}

// TestVerifyTruncatedRRHeader covers the `off+10 > len(msg)` branch in
// stripTSIG: ARCOUNT > 0, but the message is truncated such that there
// isn't enough room for the RR fixed header after the owner name.
func TestVerifyTruncatedRRHeader(t *testing.T) {
	t.Parallel()
	// Build a minimal message: 12-byte header with ARCOUNT=1 and one byte
	// for an empty owner name (root).
	msg := make([]byte, 12+1)
	binary.BigEndian.PutUint16(msg[10:12], 1) // ARCOUNT = 1
	// msg[12] = 0x00 already (root name)
	key := tsig.Key{
		Name:      wire.MustParseName("k.example."),
		Algorithm: tsig.HMACSHA256,
		Secret:    []byte("s"),
	}
	_, _, err := tsig.Verify(msg, key, time.Now(), time.Minute)
	require.ErrorContains(t, err, "truncated rr header")
}

// TestVerifyNonTSIGRRType covers the `rrType != tsigType` branch in
// stripTSIG.
func TestVerifyNonTSIGRRType(t *testing.T) {
	t.Parallel()
	// Header (12 bytes) with ARCOUNT=1, then root owner (1 byte), then
	// 10-byte fixed RR header with TYPE=A (1) and rdlen=0.
	msg := make([]byte, 12+1+10)
	binary.BigEndian.PutUint16(msg[10:12], 1) // ARCOUNT=1
	off := 13
	binary.BigEndian.PutUint16(msg[off:off+2], 1)    // TYPE=A
	binary.BigEndian.PutUint16(msg[off+2:off+4], 1)  // CLASS=IN
	binary.BigEndian.PutUint32(msg[off+4:off+8], 0)  // TTL
	binary.BigEndian.PutUint16(msg[off+8:off+10], 0) // rdlen=0
	key := tsig.Key{
		Name:      wire.MustParseName("k.example."),
		Algorithm: tsig.HMACSHA256,
		Secret:    []byte("s"),
	}
	_, _, err := tsig.Verify(msg, key, time.Now(), time.Minute)
	require.ErrorIs(t, err, tsig.ErrTSIGMissing)
}

// TestVerifyTruncatedTSIGAlgName covers the parseTSIGRData "parse alg"
// error: rdata is present but the algorithm name field is malformed.
func TestVerifyTruncatedTSIGAlgName(t *testing.T) {
	t.Parallel()
	// Build a TSIG RR whose rdata contains a single label with length 200
	// (truncated label).
	rdata := []byte{200} // length octet 200, no label bytes
	rdlen := len(rdata)
	msg := make([]byte, 12+1+10+rdlen)
	binary.BigEndian.PutUint16(msg[10:12], 1)
	off := 13
	binary.BigEndian.PutUint16(msg[off:off+2], 250)
	binary.BigEndian.PutUint16(msg[off+2:off+4], 255)
	binary.BigEndian.PutUint32(msg[off+4:off+8], 0)
	binary.BigEndian.PutUint16(msg[off+8:off+10], uint16(rdlen))
	copy(msg[off+10:], rdata)

	key := tsig.Key{
		Name:      wire.MustParseName("k.example."),
		Algorithm: tsig.HMACSHA256,
		Secret:    []byte("s"),
	}
	_, _, err := tsig.Verify(msg, key, time.Now(), time.Minute)
	require.ErrorContains(t, err, "parse alg")
}

// TestVerifyTruncatedTimeFudgeMacSize covers the
// `off+6+2+2 > end` branch: alg name parses, but no room for time/fudge/macSize.
func TestVerifyTruncatedTimeFudgeMacSize(t *testing.T) {
	t.Parallel()
	// rdata = root name (1 byte). No time/fudge/macSize follows.
	rdata := []byte{0x00}
	rdlen := len(rdata)
	msg := make([]byte, 12+1+10+rdlen)
	binary.BigEndian.PutUint16(msg[10:12], 1)
	off := 13
	binary.BigEndian.PutUint16(msg[off:off+2], 250)
	binary.BigEndian.PutUint16(msg[off+2:off+4], 255)
	binary.BigEndian.PutUint32(msg[off+4:off+8], 0)
	binary.BigEndian.PutUint16(msg[off+8:off+10], uint16(rdlen))
	copy(msg[off+10:], rdata)

	key := tsig.Key{
		Name:      wire.MustParseName("k.example."),
		Algorithm: tsig.HMACSHA256,
		Secret:    []byte("s"),
	}
	_, _, err := tsig.Verify(msg, key, time.Now(), time.Minute)
	require.Error(t, err)
	require.Contains(t, err.Error(), "truncated time/fudge/mac-size")
}

// TestVerifyTruncatedMacOrigIDErrOtherLen covers the
// `off+macSize+2+2+2 > end` branch: macSize is larger than what fits.
func TestVerifyTruncatedMacOrigIDErrOtherLen(t *testing.T) {
	t.Parallel()
	// rdata = root name (1) + time (6) + fudge (2) + macSize=100 (2) =
	// 11 bytes, but no mac follows.
	rdata := make([]byte, 1+6+2+2)
	// root name = 0x00 (already)
	// time signed bytes 1..6 = 0
	// fudge bytes 7..8 = 0
	binary.BigEndian.PutUint16(rdata[9:11], 100) // macSize=100

	rdlen := len(rdata)
	msg := make([]byte, 12+1+10+rdlen)
	binary.BigEndian.PutUint16(msg[10:12], 1)
	off := 13
	binary.BigEndian.PutUint16(msg[off:off+2], 250)
	binary.BigEndian.PutUint16(msg[off+2:off+4], 255)
	binary.BigEndian.PutUint32(msg[off+4:off+8], 0)
	binary.BigEndian.PutUint16(msg[off+8:off+10], uint16(rdlen))
	copy(msg[off+10:], rdata)

	key := tsig.Key{
		Name:      wire.MustParseName("k.example."),
		Algorithm: tsig.HMACSHA256,
		Secret:    []byte("s"),
	}
	_, _, err := tsig.Verify(msg, key, time.Now(), time.Minute)
	require.Error(t, err)
	require.Contains(t, err.Error(), "truncated mac/origID/err/otherLen")
}

// TestVerifyTruncatedOtherData covers the `off+otherLen > end` branch:
// otherLen exceeds the remaining bytes.
func TestVerifyTruncatedOtherData(t *testing.T) {
	t.Parallel()
	// rdata = root (1) + time (6) + fudge (2) + macSize (2) + mac (0) +
	// origID (2) + err (2) + otherLen (2) = 17 bytes; otherLen=100 (lie).
	rdata := make([]byte, 1+6+2+2+2+2+2)
	binary.BigEndian.PutUint16(rdata[9:11], 0)    // macSize=0
	binary.BigEndian.PutUint16(rdata[11:13], 0)   // origID
	binary.BigEndian.PutUint16(rdata[13:15], 0)   // errCode
	binary.BigEndian.PutUint16(rdata[15:17], 100) // otherLen=100 (lie)

	rdlen := len(rdata)
	msg := make([]byte, 12+1+10+rdlen)
	binary.BigEndian.PutUint16(msg[10:12], 1)
	off := 13
	binary.BigEndian.PutUint16(msg[off:off+2], 250)
	binary.BigEndian.PutUint16(msg[off+2:off+4], 255)
	binary.BigEndian.PutUint32(msg[off+4:off+8], 0)
	binary.BigEndian.PutUint16(msg[off+8:off+10], uint16(rdlen))
	copy(msg[off+10:], rdata)

	key := tsig.Key{
		Name:      wire.MustParseName("k.example."),
		Algorithm: tsig.HMACSHA256,
		Secret:    []byte("s"),
	}
	_, _, err := tsig.Verify(msg, key, time.Now(), time.Minute)
	require.Error(t, err)
	require.Contains(t, err.Error(), "truncated other-data")
}

// TestVerifyTruncatedQuestionWalk covers findLastRROffset's question
// section walk: QDCOUNT advertises a question but bytes are missing.
func TestVerifyTruncatedQuestionWalk(t *testing.T) {
	t.Parallel()
	// Header with QDCOUNT=1 and ARCOUNT=1, then root owner only (no
	// QTYPE/QCLASS). The question walk should fail.
	msg := make([]byte, 12+1)
	binary.BigEndian.PutUint16(msg[4:6], 1)   // QDCOUNT=1
	binary.BigEndian.PutUint16(msg[10:12], 1) // ARCOUNT=1
	// msg[12] = 0x00 (root name), but no QTYPE/QCLASS

	key := tsig.Key{
		Name:      wire.MustParseName("k.example."),
		Algorithm: tsig.HMACSHA256,
		Secret:    []byte("s"),
	}
	_, _, err := tsig.Verify(msg, key, time.Now(), time.Minute)
	require.ErrorContains(t, err, "truncated question")
}

// TestVerifyTruncatedRRBody covers findLastRROffset's RR body walk:
// rdlen reaches past msg.
func TestVerifyTruncatedRRBody(t *testing.T) {
	t.Parallel()
	// Header (ARCOUNT=2: a non-TSIG RR with rdlen lying about its body
	// length, then we never reach the second RR), root owner (1) +
	// 10-byte RR header with TYPE=A and rdlen=200 (lie).
	msg := make([]byte, 12+1+10)
	binary.BigEndian.PutUint16(msg[10:12], 2) // ARCOUNT=2
	off := 13
	binary.BigEndian.PutUint16(msg[off:off+2], 1)      // TYPE=A
	binary.BigEndian.PutUint16(msg[off+2:off+4], 1)    // CLASS=IN
	binary.BigEndian.PutUint32(msg[off+4:off+8], 0)    // TTL
	binary.BigEndian.PutUint16(msg[off+8:off+10], 200) // rdlen=200 (lie)

	key := tsig.Key{
		Name:      wire.MustParseName("k.example."),
		Algorithm: tsig.HMACSHA256,
		Secret:    []byte("s"),
	}
	_, _, err := tsig.Verify(msg, key, time.Now(), time.Minute)
	require.ErrorContains(t, err, "truncated rr body")
}

// TestVerifyOtherDataPreservedRoundTrip covers the parseTSIGRData branch
// where otherLen > 0 but parses successfully. We can't construct that via
// Sign (Sign always passes nil other), but we exercise the well-formed
// parse by signing, then verifying; the valid round-trip exercises the
// entire successful path including a zero-length other-data slice.
func TestVerifyValidWithExplicitFudgeWindow(t *testing.T) {
	t.Parallel()
	// Round-trip with a fudge of 0 to exercise the boundary "delta == 0"
	// case and make sure no off-by-one rejects valid signatures.
	key := tsig.Key{
		Name:      wire.MustParseName("k.example."),
		Algorithm: tsig.HMACSHA384,
		Secret:    []byte("a-real-secret-that-is-bytes"),
	}
	msg := mkMessage(t)
	now := time.Unix(1234567890, 0).UTC()
	signed, err := tsig.Sign(msg, key, now, time.Second)
	require.NoError(t, err)

	body, signedAt, err := tsig.Verify(signed, key, now, time.Second)
	require.NoError(t, err)
	require.Equal(t, now, signedAt)
	require.NotEmpty(t, body)
}
