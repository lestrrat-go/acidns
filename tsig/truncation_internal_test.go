package tsig

import (
	"crypto/rand"
	"encoding/binary"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/stretchr/testify/require"
)

// signWithTruncatedMAC produces a TSIG-signed message whose MAC is
// truncated to mLen octets. It mirrors signWithPrefix internally but
// shortens the MAC bytes (and the rdlen) before appending. Used to
// drive the spec-permitted truncation path of verifyWithPrefix.
func signWithTruncatedMAC(t *testing.T, msg []byte, key Key, now time.Time, fudge time.Duration, mLen int) []byte {
	t.Helper()
	algName := wire.MustParseName(string(key.algorithm))
	timeSigned := uint64(now.Unix())
	fudgeSecs := uint16(fudge.Seconds())

	input := buildSigningInput(msg, key.name, algName, nil, timeSigned, fudgeSecs, 0, nil, false)
	mac, err := computeHMAC(key, input)
	require.NoError(t, err)
	require.LessOrEqual(t, mLen, len(mac))

	origID := binary.BigEndian.Uint16(msg[0:2])
	rdata := buildTSIGRData(algName, timeSigned, fudgeSecs, mac[:mLen], origID, 0, nil)
	out := append([]byte(nil), msg...)
	out = appendTSIGRR(out, key.name, rdata)
	arcount := binary.BigEndian.Uint16(out[10:12])
	binary.BigEndian.PutUint16(out[10:12], arcount+1)
	return out
}

func TestVerifyAcceptsTruncatedMAC(t *testing.T) {
	t.Parallel()
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	key := NewKey(wire.MustParseName("test.key"), HMACSHA256, secret)
	now := time.Now().Truncate(time.Second)

	q, err := wire.NewMessageBuilder().
		ID(0xabcd).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	msg, err := wire.Marshal(q)
	require.NoError(t, err)

	// Truncate to the floor (16 octets for HMAC-SHA-256).
	signed := signWithTruncatedMAC(t, msg, key, now, 5*time.Minute, 16)

	body, _, _, err := VerifyMAC(signed, key, now, 5*time.Minute)
	require.NoError(t, err, "spec-permitted truncated MAC must verify")
	require.NotEmpty(t, body)
}

func TestVerifyRejectsBelowFloor(t *testing.T) {
	t.Parallel()
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	key := NewKey(wire.MustParseName("test.key"), HMACSHA256, secret)
	now := time.Now().Truncate(time.Second)

	q, err := wire.NewMessageBuilder().
		ID(0xabcd).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	require.NoError(t, err)
	msg, err := wire.Marshal(q)
	require.NoError(t, err)

	signed := signWithTruncatedMAC(t, msg, key, now, 5*time.Minute, 8) // below floor

	_, _, _, err = VerifyMAC(signed, key, now, 5*time.Minute) //nolint:dogsled // 4-tuple API
	require.ErrorIs(t, err, ErrBadTruncation)
}

// TestFindLastRROffsetRejectsTSIGOutsideAR exercises the RFC 8945 §5.1
// section-placement guard in findLastRROffset: a message whose last RR
// falls in NS (ANCOUNT+NSCOUNT > 0, ARCOUNT == 0) must be rejected
// rather than treated as a TSIG candidate.
func TestFindLastRROffsetRejectsTSIGOutsideAR(t *testing.T) {
	t.Parallel()
	// Header (12 bytes) with NSCOUNT=1, ARCOUNT=0; root owner (1 byte) +
	// 10-byte fixed RR header with TYPE=TSIG (250) and rdlen=0. The
	// record sits in the AUTHORITY section.
	msg := make([]byte, 12+1+10)
	binary.BigEndian.PutUint16(msg[8:10], 1) // NSCOUNT=1
	binary.BigEndian.PutUint16(msg[10:12], 0)
	off := 13
	binary.BigEndian.PutUint16(msg[off:off+2], 250)  // TYPE=TSIG
	binary.BigEndian.PutUint16(msg[off+2:off+4], 1)  // CLASS=IN
	binary.BigEndian.PutUint32(msg[off+4:off+8], 0)  // TTL
	binary.BigEndian.PutUint16(msg[off+8:off+10], 0) // rdlen=0

	_, err := findLastRROffset(msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "last RR not in additional section")
}

// TestFindLastRROffsetAcceptsLastInAR verifies the well-formed case:
// last RR sits in AR and findLastRROffset returns the owner-name offset
// of that record.
func TestFindLastRROffsetAcceptsLastInAR(t *testing.T) {
	t.Parallel()
	// Header with ANCOUNT=0, NSCOUNT=0, ARCOUNT=1; root owner + 10-byte
	// header with TYPE=TSIG, rdlen=0.
	msg := make([]byte, 12+1+10)
	binary.BigEndian.PutUint16(msg[10:12], 1) // ARCOUNT=1
	off := 13
	binary.BigEndian.PutUint16(msg[off:off+2], 250)
	binary.BigEndian.PutUint16(msg[off+2:off+4], 1)
	binary.BigEndian.PutUint32(msg[off+4:off+8], 0)
	binary.BigEndian.PutUint16(msg[off+8:off+10], 0)

	got, err := findLastRROffset(msg)
	require.NoError(t, err)
	require.Equal(t, 12, got)
}
