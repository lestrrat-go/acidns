package sig0_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/sig0"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/stretchr/testify/require"
)

// rsaPubWire encodes (e, n) in the DNSKEY RSA wire form (RFC 3110).
func rsaPubWire(t *testing.T, priv *rsa.PrivateKey) []byte {
	t.Helper()
	expBytes := big.NewInt(int64(priv.E)).Bytes()
	out := make([]byte, 0, 1+len(expBytes)+len(priv.N.Bytes()))
	out = append(out, byte(len(expBytes)))
	out = append(out, expBytes...)
	out = append(out, priv.N.Bytes()...)
	return out
}

// rsaPubWireLong encodes RSA pubkey with 3-byte length prefix (e length > 255).
// Uses leading 0 byte + 16-bit length per RFC 3110.
func rsaPubWireLong(t *testing.T, priv *rsa.PrivateKey) []byte {
	t.Helper()
	expBytes := big.NewInt(int64(priv.E)).Bytes()
	out := make([]byte, 0, 3+len(expBytes)+len(priv.N.Bytes()))
	out = append(out, 0)
	out = binary.BigEndian.AppendUint16(out, uint16(len(expBytes)))
	out = append(out, expBytes...)
	out = append(out, priv.N.Bytes()...)
	return out
}

func TestSignVerifyRSASHA512(t *testing.T) {
	t.Parallel()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub := rsaPubWire(t, priv)

	signer := wire.MustParseName("test.signer")
	msg := mkMessage(t)
	now := time.Now().Truncate(time.Second).UTC()

	signed, err := sig0.Sign(msg, signer, rdata.AlgRSASHA512, 9999,
		func(payload []byte) ([]byte, error) {
			h := sha512.Sum512(payload)
			return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA512, h[:])
		}, now, time.Hour)
	require.NoError(t, err)

	_, err = sig0.Verify(signed, rdata.AlgRSASHA512, pub, signer, now)
	require.NoError(t, err)
}

func TestSignVerifyECDSAP384(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	pub := append(priv.PublicKey.X.FillBytes(make([]byte, 48)), priv.PublicKey.Y.FillBytes(make([]byte, 48))...)

	signer := wire.MustParseName("test.signer")
	msg := mkMessage(t)
	now := time.Now().Truncate(time.Second).UTC()

	signed, err := sig0.Sign(msg, signer, rdata.AlgECDSAP384SHA384, 4242,
		func(payload []byte) ([]byte, error) {
			h := sha512.Sum384(payload)
			r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
			if err != nil {
				return nil, err
			}
			out := make([]byte, 96)
			r.FillBytes(out[:48])
			s.FillBytes(out[48:])
			return out, nil
		}, now, time.Hour)
	require.NoError(t, err)

	_, err = sig0.Verify(signed, rdata.AlgECDSAP384SHA384, pub, signer, now)
	require.NoError(t, err)
}

func TestSignMsgTooShort(t *testing.T) {
	t.Parallel()
	_, err := sig0.Sign([]byte{1, 2, 3}, wire.MustParseName("s"), rdata.AlgED25519, 1,
		func([]byte) ([]byte, error) { return nil, nil },
		time.Now(), time.Hour)
	require.Error(t, err)
}

func TestSignCallbackError(t *testing.T) {
	t.Parallel()
	msg := mkMessage(t)
	wantErr := errors.New("boom")
	_, err := sig0.Sign(msg, wire.MustParseName("s"), rdata.AlgED25519, 1,
		func([]byte) ([]byte, error) { return nil, wantErr },
		time.Now(), time.Hour)
	require.ErrorIs(t, err, wantErr)
}

func TestVerifyMsgTooShort(t *testing.T) {
	t.Parallel()
	_, err := sig0.Verify([]byte{1}, rdata.AlgED25519, nil, wire.MustParseName("s"), time.Now())
	require.Error(t, err)
}

func TestVerifyNoSIGRecord(t *testing.T) {
	t.Parallel()
	msg := mkMessage(t)
	_, err := sig0.Verify(msg, rdata.AlgED25519, nil, wire.MustParseName("s"), time.Now())
	require.ErrorIs(t, err, sig0.ErrSIGMissing)
}

func TestVerifySignerMismatch(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer := wire.MustParseName("alice.example")
	msg := mkMessage(t)
	now := time.Now().Truncate(time.Second).UTC()
	signed, err := sig0.Sign(msg, signer, rdata.AlgED25519, 1, func(p []byte) ([]byte, error) {
		return ed25519.Sign(priv, p), nil
	}, now, time.Hour)
	require.NoError(t, err)
	_, err = sig0.Verify(signed, rdata.AlgED25519, pub, wire.MustParseName("bob.example"), now)
	require.Error(t, err)
	require.Contains(t, err.Error(), "signer mismatch")
}

func TestVerifyAlgorithmMismatch(t *testing.T) {
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer := wire.MustParseName("s")
	msg := mkMessage(t)
	now := time.Now().Truncate(time.Second).UTC()
	signed, err := sig0.Sign(msg, signer, rdata.AlgED25519, 1, func(p []byte) ([]byte, error) {
		return ed25519.Sign(priv, p), nil
	}, now, time.Hour)
	require.NoError(t, err)
	// Verifier expects RSA but the SIG announces Ed25519.
	_, err = sig0.Verify(signed, rdata.AlgRSASHA256, nil, signer, now)
	require.ErrorIs(t, err, sig0.ErrUnsupportedAlg)
}

func TestVerifyInceptionInFuture(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer := wire.MustParseName("s")
	msg := mkMessage(t)
	signedAt := time.Now().Truncate(time.Second).UTC()
	signed, err := sig0.Sign(msg, signer, rdata.AlgED25519, 1, func(p []byte) ([]byte, error) {
		return ed25519.Sign(priv, p), nil
	}, signedAt, time.Hour)
	require.NoError(t, err)
	// Verifier clock is well before inception.
	_, err = sig0.Verify(signed, rdata.AlgED25519, pub, signer, signedAt.Add(-2*time.Hour))
	require.ErrorIs(t, err, sig0.ErrBadTime)
}

func TestVerifyWrongKey(t *testing.T) {
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer := wire.MustParseName("s")
	msg := mkMessage(t)
	now := time.Now().Truncate(time.Second).UTC()
	signed, err := sig0.Sign(msg, signer, rdata.AlgED25519, 1, func(p []byte) ([]byte, error) {
		return ed25519.Sign(priv, p), nil
	}, now, time.Hour)
	require.NoError(t, err)
	_, err = sig0.Verify(signed, rdata.AlgED25519, otherPub, signer, now)
	require.ErrorIs(t, err, sig0.ErrBadSignature)
}

func TestVerifyEd25519WrongPubkeySize(t *testing.T) {
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer := wire.MustParseName("s")
	msg := mkMessage(t)
	now := time.Now().Truncate(time.Second).UTC()
	signed, err := sig0.Sign(msg, signer, rdata.AlgED25519, 1, func(p []byte) ([]byte, error) {
		return ed25519.Sign(priv, p), nil
	}, now, time.Hour)
	require.NoError(t, err)
	_, err = sig0.Verify(signed, rdata.AlgED25519, []byte{1, 2, 3}, signer, now)
	require.ErrorIs(t, err, sig0.ErrBadSignature)
	require.Contains(t, err.Error(), "ed25519 pubkey wrong size")
}

func TestVerifyECDSAWrongPubkeySize(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer := wire.MustParseName("s")
	msg := mkMessage(t)
	now := time.Now().Truncate(time.Second).UTC()
	signed, err := sig0.Sign(msg, signer, rdata.AlgECDSAP256SHA256, 1,
		func(p []byte) ([]byte, error) {
			h := sha256.Sum256(p)
			r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
			if err != nil {
				return nil, err
			}
			out := make([]byte, 64)
			r.FillBytes(out[:32])
			s.FillBytes(out[32:])
			return out, nil
		}, now, time.Hour)
	require.NoError(t, err)

	_, err = sig0.Verify(signed, rdata.AlgECDSAP256SHA256, []byte{1, 2}, signer, now)
	require.ErrorIs(t, err, sig0.ErrBadSignature)
	require.Contains(t, err.Error(), "pubkey wrong size")
}

func TestVerifyECDSAWrongSignatureSize(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := append(priv.PublicKey.X.FillBytes(make([]byte, 32)), priv.PublicKey.Y.FillBytes(make([]byte, 32))...)
	signer := wire.MustParseName("s")
	msg := mkMessage(t)
	now := time.Now().Truncate(time.Second).UTC()
	// Sign callback returns garbage of wrong length.
	signed, err := sig0.Sign(msg, signer, rdata.AlgECDSAP256SHA256, 1,
		func([]byte) ([]byte, error) { return []byte{1, 2, 3}, nil },
		now, time.Hour)
	require.NoError(t, err)

	_, err = sig0.Verify(signed, rdata.AlgECDSAP256SHA256, pub, signer, now)
	require.ErrorIs(t, err, sig0.ErrBadSignature)
	require.Contains(t, err.Error(), "signature wrong size")
}

func TestVerifyRSAParseError(t *testing.T) {
	t.Parallel()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer := wire.MustParseName("s")
	msg := mkMessage(t)
	now := time.Now().Truncate(time.Second).UTC()
	signed, err := sig0.Sign(msg, signer, rdata.AlgRSASHA256, 1,
		func(p []byte) ([]byte, error) {
			h := sha256.Sum256(p)
			return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
		}, now, time.Hour)
	require.NoError(t, err)

	// Empty pubkey → parseRSAPublic returns "too short".
	_, err = sig0.Verify(signed, rdata.AlgRSASHA256, nil, signer, now)
	require.Error(t, err)
}

func TestVerifyRSABadSignature(t *testing.T) {
	t.Parallel()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub := rsaPubWire(t, priv)
	signer := wire.MustParseName("s")
	msg := mkMessage(t)
	now := time.Now().Truncate(time.Second).UTC()

	// Produce a syntactically-OK but wrong signature.
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signed, err := sig0.Sign(msg, signer, rdata.AlgRSASHA256, 1,
		func(p []byte) ([]byte, error) {
			h := sha256.Sum256(p)
			return rsa.SignPKCS1v15(rand.Reader, other, crypto.SHA256, h[:])
		}, now, time.Hour)
	require.NoError(t, err)

	_, err = sig0.Verify(signed, rdata.AlgRSASHA256, pub, signer, now)
	require.ErrorIs(t, err, sig0.ErrBadSignature)
}

func TestVerifyRSASHA512BadSignature(t *testing.T) {
	t.Parallel()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub := rsaPubWire(t, priv)
	signer := wire.MustParseName("s")
	msg := mkMessage(t)
	now := time.Now().Truncate(time.Second).UTC()

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signed, err := sig0.Sign(msg, signer, rdata.AlgRSASHA512, 1,
		func(p []byte) ([]byte, error) {
			h := sha512.Sum512(p)
			return rsa.SignPKCS1v15(rand.Reader, other, crypto.SHA512, h[:])
		}, now, time.Hour)
	require.NoError(t, err)

	_, err = sig0.Verify(signed, rdata.AlgRSASHA512, pub, signer, now)
	require.ErrorIs(t, err, sig0.ErrBadSignature)
}

func TestVerifyRSASHA512ParseError(t *testing.T) {
	t.Parallel()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer := wire.MustParseName("s")
	msg := mkMessage(t)
	now := time.Now().Truncate(time.Second).UTC()
	signed, err := sig0.Sign(msg, signer, rdata.AlgRSASHA512, 1,
		func(p []byte) ([]byte, error) {
			h := sha512.Sum512(p)
			return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA512, h[:])
		}, now, time.Hour)
	require.NoError(t, err)

	_, err = sig0.Verify(signed, rdata.AlgRSASHA512, nil, signer, now)
	require.Error(t, err)
}

func TestVerifyRSALongExpForm(t *testing.T) {
	t.Parallel()
	// Cover the b[0] == 0 (3-byte length prefix) branch in parseRSAPublic by
	// hand-encoding the public key in long form. Real RSA exponents are short,
	// so this just exercises the parser path; verification should still succeed.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub := rsaPubWireLong(t, priv)
	signer := wire.MustParseName("s")
	msg := mkMessage(t)
	now := time.Now().Truncate(time.Second).UTC()
	signed, err := sig0.Sign(msg, signer, rdata.AlgRSASHA256, 1,
		func(p []byte) ([]byte, error) {
			h := sha256.Sum256(p)
			return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
		}, now, time.Hour)
	require.NoError(t, err)
	_, err = sig0.Verify(signed, rdata.AlgRSASHA256, pub, signer, now)
	require.NoError(t, err)
}

// --- stripSIG / findLastRROffset edge cases driven via Verify ---

func ed25519Signed(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer := wire.MustParseName("s")
	msg := mkMessage(t)
	signed, err := sig0.Sign(msg, signer, rdata.AlgED25519, 1, func(p []byte) ([]byte, error) {
		return ed25519.Sign(priv, p), nil
	}, time.Now().Truncate(time.Second).UTC(), time.Hour)
	require.NoError(t, err)
	return signed
}

func TestVerifyTruncatedRRHeader(t *testing.T) {
	t.Parallel()
	signed := ed25519Signed(t)
	// Truncate so the SIG record's 10-byte fixed header doesn't fit.
	short := append([]byte(nil), signed[:len(signed)-len(signed)+13]...)
	// Restore arcount from original (keeps sanity in tests for short header path).
	if len(short) >= 12 {
		binary.BigEndian.PutUint16(short[10:12], 1)
	}
	_, err := sig0.Verify(short, rdata.AlgED25519, make([]byte, 32), wire.MustParseName("s"), time.Now())
	require.Error(t, err)
}

func TestVerifyTruncatedRdata(t *testing.T) {
	t.Parallel()
	signed := ed25519Signed(t)
	// Drop the trailing signature bytes — rdata length still claims original size.
	chopped := append([]byte(nil), signed[:len(signed)-20]...)
	_, err := sig0.Verify(chopped, rdata.AlgED25519, make([]byte, 32), wire.MustParseName("s"), time.Now())
	require.Error(t, err)
}

func TestVerifyTruncatedSIGHeader(t *testing.T) {
	t.Parallel()
	// Hand-craft a message with arcount=1 and a SIG RR whose rdata is < 18 bytes.
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[10:12], 1) // arcount = 1
	// owner=root, type=24, class=255, ttl=0, rdlen=5, rdata=5 zero bytes
	rr := []byte{0}
	rr = binary.BigEndian.AppendUint16(rr, 24)
	rr = binary.BigEndian.AppendUint16(rr, 255)
	rr = binary.BigEndian.AppendUint32(rr, 0)
	rr = binary.BigEndian.AppendUint16(rr, 5)
	rr = append(rr, 0, 0, 0, 0, 0)
	msg := append(hdr, rr...)
	_, err := sig0.Verify(msg, rdata.AlgED25519, make([]byte, 32), wire.MustParseName("s"), time.Now())
	require.Error(t, err)
}

func TestVerifyWrongRRType(t *testing.T) {
	t.Parallel()
	// arcount=1 but the trailing RR isn't SIG.
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[10:12], 1)
	rr := []byte{0}
	rr = binary.BigEndian.AppendUint16(rr, 1) // type A — not SIG
	rr = binary.BigEndian.AppendUint16(rr, 1) // class IN
	rr = binary.BigEndian.AppendUint32(rr, 0)
	rr = binary.BigEndian.AppendUint16(rr, 4)
	rr = append(rr, 127, 0, 0, 1)
	msg := append(hdr, rr...)
	_, err := sig0.Verify(msg, rdata.AlgED25519, make([]byte, 32), wire.MustParseName("s"), time.Now())
	require.ErrorIs(t, err, sig0.ErrSIGMissing)
}

func TestVerifyTruncatedQuestion(t *testing.T) {
	t.Parallel()
	// qdcount=1 but the question doesn't fit (no QTYPE/QCLASS bytes).
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[4:6], 1)   // qdcount = 1
	binary.BigEndian.PutUint16(hdr[10:12], 1) // arcount = 1 to bypass early SIG check
	msg := append(hdr, 0)                     // root name only — no QTYPE/QCLASS
	_, err := sig0.Verify(msg, rdata.AlgED25519, make([]byte, 32), wire.MustParseName("s"), time.Now())
	require.Error(t, err)
}

func TestVerifyTruncatedRRBody(t *testing.T) {
	t.Parallel()
	// arcount=1, header claims rdlen=10 but only 2 bytes follow.
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[10:12], 1)
	rr := []byte{0}
	rr = binary.BigEndian.AppendUint16(rr, 24)
	rr = binary.BigEndian.AppendUint16(rr, 255)
	rr = binary.BigEndian.AppendUint32(rr, 0)
	rr = binary.BigEndian.AppendUint16(rr, 10)
	rr = append(rr, 0, 0)
	msg := append(hdr, rr...)
	_, err := sig0.Verify(msg, rdata.AlgED25519, make([]byte, 32), wire.MustParseName("s"), time.Now())
	require.Error(t, err)
}

func TestVerifyOwnerParseError(t *testing.T) {
	t.Parallel()
	// arcount=1, an owner name byte that exceeds the buffer.
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[10:12], 1)
	// label length 64 (>63) is invalid → DecodeName fails.
	msg := append(hdr, 0xff, 0x00)
	_, err := sig0.Verify(msg, rdata.AlgED25519, make([]byte, 32), wire.MustParseName("s"), time.Now())
	require.Error(t, err)
}

func TestVerifySignerParseError(t *testing.T) {
	t.Parallel()
	// Build a SIG(0) RR whose signer-name field is malformed.
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[10:12], 1)

	// SIG fixed prefix: 18 bytes (type(2) alg(1) lab(1) ttl(4) exp(4) inc(4) tag(2)).
	prefix := make([]byte, 18)
	// Then a malformed name byte.
	signerBad := []byte{0xff} // length > 63
	rdataBytes := append(append([]byte(nil), prefix...), signerBad...)

	rr := []byte{0}
	rr = binary.BigEndian.AppendUint16(rr, 24)
	rr = binary.BigEndian.AppendUint16(rr, 255)
	rr = binary.BigEndian.AppendUint32(rr, 0)
	rr = binary.BigEndian.AppendUint16(rr, uint16(len(rdataBytes)))
	rr = append(rr, rdataBytes...)
	msg := append(hdr, rr...)
	_, err := sig0.Verify(msg, rdata.AlgED25519, make([]byte, 32), wire.MustParseName("s"), time.Now())
	require.Error(t, err)
}

func TestVerifySignerOverrunsRdata(t *testing.T) {
	t.Parallel()
	// SIG rdata where the signer name extends past rdlen.
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[10:12], 1)

	prefix := make([]byte, 18)
	// Signer name "a." in wire form = [1 'a' 0] = 3 bytes, but we'll lie about
	// rdlen so that the parsed signer ends past rdataEnd.
	signerName := []byte{1, 'a', 0}
	rdataBytes := append(append([]byte(nil), prefix...), signerName...)
	// Truncate rdlen so parsed signer would land beyond rdataEnd.
	declaredRdlen := uint16(len(prefix) + 1) // claim only 19 bytes — signer (3 bytes) overruns.

	rr := []byte{0}
	rr = binary.BigEndian.AppendUint16(rr, 24)
	rr = binary.BigEndian.AppendUint16(rr, 255)
	rr = binary.BigEndian.AppendUint32(rr, 0)
	rr = binary.BigEndian.AppendUint16(rr, declaredRdlen)
	// Append actual rdata of full length anyway (so total msg is large enough).
	rr = append(rr, rdataBytes...)
	msg := append(hdr, rr...)
	_, err := sig0.Verify(msg, rdata.AlgED25519, make([]byte, 32), wire.MustParseName("s"), time.Now())
	require.Error(t, err)
}

// --- parseRSAPublic edge cases via verifySignature ---

func TestVerifyRSAEmptyPubkey(t *testing.T) {
	t.Parallel()
	signed := mustRSASigned(t, rdata.AlgRSASHA256)
	_, err := sig0.Verify(signed, rdata.AlgRSASHA256, []byte{}, wire.MustParseName("s"), time.Now())
	require.Error(t, err)
}

func TestVerifyRSALongFormTruncated(t *testing.T) {
	t.Parallel()
	signed := mustRSASigned(t, rdata.AlgRSASHA256)
	// b[0]==0 but only 2 bytes total → "rsa pubkey truncated".
	_, err := sig0.Verify(signed, rdata.AlgRSASHA256, []byte{0, 0}, wire.MustParseName("s"), time.Now())
	require.Error(t, err)
}

func TestVerifyRSATruncatedExp(t *testing.T) {
	t.Parallel()
	signed := mustRSASigned(t, rdata.AlgRSASHA256)
	// explen = 5 but only 1 exp byte present.
	_, err := sig0.Verify(signed, rdata.AlgRSASHA256, []byte{5, 1}, wire.MustParseName("s"), time.Now())
	require.Error(t, err)
}

func TestVerifyRSAExponentTooLarge(t *testing.T) {
	t.Parallel()
	signed := mustRSASigned(t, rdata.AlgRSASHA256)
	// 9-byte exponent overflows int64 ⇒ "rsa exponent too large".
	pub := []byte{9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x02}
	_, err := sig0.Verify(signed, rdata.AlgRSASHA256, pub, wire.MustParseName("s"), time.Now())
	require.Error(t, err)
}

func mustRSASigned(t *testing.T, alg rdata.DNSSECAlgorithm) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer := wire.MustParseName("s")
	msg := mkMessage(t)
	now := time.Now().Truncate(time.Second).UTC()
	signed, err := sig0.Sign(msg, signer, alg, 1,
		func(p []byte) ([]byte, error) {
			switch alg {
			case rdata.AlgRSASHA512:
				h := sha512.Sum512(p)
				return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA512, h[:])
			default:
				h := sha256.Sum256(p)
				return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
			}
		}, now, time.Hour)
	require.NoError(t, err)
	return signed
}
