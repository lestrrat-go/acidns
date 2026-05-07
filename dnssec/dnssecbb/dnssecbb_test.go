package dnssecbb_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA-1 still required by DS digest type 1.
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"math/big"
	"testing"

	"github.com/lestrrat-go/acidns/dnssec/dnssecbb"
	"github.com/stretchr/testify/require"
)

// encodeRSAPublic encodes an *rsa.PublicKey in the RFC 3110 form.
func encodeRSAPublic(t *testing.T, pub *rsa.PublicKey) []byte {
	t.Helper()
	expBytes := new(big.Int).SetInt64(int64(pub.E)).Bytes()
	modBytes := pub.N.Bytes()
	out := make([]byte, 0, 3+len(expBytes)+len(modBytes))
	if len(expBytes) <= 255 {
		out = append(out, byte(len(expBytes)))
	} else {
		out = append(out, 0, byte(len(expBytes)>>8), byte(len(expBytes)))
	}
	out = append(out, expBytes...)
	out = append(out, modBytes...)
	return out
}

func TestParseRSAPublic(t *testing.T) {
	t.Parallel()

	t.Run("short form round trip", func(t *testing.T) {
		t.Parallel()
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		enc := encodeRSAPublic(t, &key.PublicKey)
		got, err := dnssecbb.ParseRSAPublic(enc)
		require.NoError(t, err)
		require.Equal(t, key.PublicKey.E, got.E)
		require.Equal(t, 0, key.PublicKey.N.Cmp(got.N))
	})

	t.Run("long form (leading zero) round trip", func(t *testing.T) {
		t.Parallel()
		// Build a synthetic encoding: 0x00 || 2-byte explen || exponent || modulus.
		// We can't easily make a real key with >255-byte exponent, but the parser
		// only cares about field lengths.
		modulus := new(big.Int).Lsh(big.NewInt(1), 2048)
		modulus.SetBit(modulus, 0, 1)
		expBytes := []byte{0x01, 0x00, 0x01} // 65537
		modBytes := modulus.Bytes()
		enc := make([]byte, 0, 3+len(expBytes)+len(modBytes))
		enc = append(enc, 0x00, 0x00, byte(len(expBytes)))
		enc = append(enc, expBytes...)
		enc = append(enc, modBytes...)
		got, err := dnssecbb.ParseRSAPublic(enc)
		require.NoError(t, err)
		require.Equal(t, 65537, got.E)
		require.Equal(t, 0, modulus.Cmp(got.N))
	})

	t.Run("empty input", func(t *testing.T) {
		t.Parallel()
		_, err := dnssecbb.ParseRSAPublic(nil)
		require.Error(t, err)
		_, err = dnssecbb.ParseRSAPublic([]byte{})
		require.Error(t, err)
	})

	t.Run("long form truncated header", func(t *testing.T) {
		t.Parallel()
		_, err := dnssecbb.ParseRSAPublic([]byte{0x00, 0x01})
		require.Error(t, err)
	})

	t.Run("truncated exponent", func(t *testing.T) {
		t.Parallel()
		// Short form claims a 5-byte exponent but only 2 bytes follow.
		_, err := dnssecbb.ParseRSAPublic([]byte{0x05, 0x01, 0x00})
		require.Error(t, err)
	})

	t.Run("exponent too large", func(t *testing.T) {
		t.Parallel()
		// Exponent length 9 (>8 bytes -> doesn't fit in int64).
		buf := []byte{0x09}
		buf = append(buf, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}...)
		buf = append(buf, []byte{0x01, 0x02, 0x03}...) // modulus
		_, err := dnssecbb.ParseRSAPublic(buf)
		require.Error(t, err)
	})
}

func TestVerifyRSA(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	data := []byte("the quick brown fox jumps over the lazy dog")

	t.Run("RSASHA256 verify", func(t *testing.T) {
		t.Parallel()
		h := sha256.Sum256(data)
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
		require.NoError(t, err)
		require.NoError(t, dnssecbb.VerifyRSA(dnssecbb.AlgRSASHA256, &key.PublicKey, data, sig))
	})

	t.Run("RSASHA256 mismatch", func(t *testing.T) {
		t.Parallel()
		h := sha256.Sum256(data)
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
		require.NoError(t, err)
		err = dnssecbb.VerifyRSA(dnssecbb.AlgRSASHA256, &key.PublicKey, []byte("tampered"), sig)
		require.Error(t, err)
		require.ErrorIs(t, err, dnssecbb.ErrSignatureMismatch)
	})

	t.Run("RSASHA512 verify", func(t *testing.T) {
		t.Parallel()
		h := sha512.Sum512(data)
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA512, h[:])
		require.NoError(t, err)
		require.NoError(t, dnssecbb.VerifyRSA(dnssecbb.AlgRSASHA512, &key.PublicKey, data, sig))
	})

	t.Run("RSASHA512 mismatch", func(t *testing.T) {
		t.Parallel()
		h := sha512.Sum512(data)
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA512, h[:])
		require.NoError(t, err)
		err = dnssecbb.VerifyRSA(dnssecbb.AlgRSASHA512, &key.PublicKey, []byte("tampered"), sig)
		require.Error(t, err)
		require.ErrorIs(t, err, dnssecbb.ErrSignatureMismatch)
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		t.Parallel()
		err := dnssecbb.VerifyRSA(dnssecbb.AlgED25519, &key.PublicKey, data, []byte{0x00})
		require.Error(t, err)
		require.ErrorIs(t, err, dnssecbb.ErrUnsupportedAlgorithm)
	})
}

func ecdsaRawSig(t *testing.T, key *ecdsa.PrivateKey, size int, hashFn func() hash.Hash, data []byte) []byte {
	t.Helper()
	hh := hashFn()
	hh.Write(data)
	digest := hh.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	require.NoError(t, err)
	sig := make([]byte, 2*size)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(sig[size-len(rb):size], rb)
	copy(sig[2*size-len(sb):], sb)
	return sig
}

func ecdsaRawPub(key *ecdsa.PrivateKey, size int) []byte {
	pub := make([]byte, 2*size)
	xb := key.PublicKey.X.Bytes()
	yb := key.PublicKey.Y.Bytes()
	copy(pub[size-len(xb):size], xb)
	copy(pub[2*size-len(yb):], yb)
	return pub
}

func TestVerifyECDSA(t *testing.T) {
	t.Parallel()

	t.Run("P-256 round trip", func(t *testing.T) {
		t.Parallel()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		data := []byte("payload P-256")
		pub := ecdsaRawPub(key, 32)
		sig := ecdsaRawSig(t, key, 32, sha256.New, data)
		require.NoError(t, dnssecbb.VerifyECDSAP256(data, pub, sig))
	})

	t.Run("P-256 tampered data", func(t *testing.T) {
		t.Parallel()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		data := []byte("payload P-256")
		pub := ecdsaRawPub(key, 32)
		sig := ecdsaRawSig(t, key, 32, sha256.New, data)
		err = dnssecbb.VerifyECDSAP256([]byte("tampered"), pub, sig)
		require.Error(t, err)
		require.ErrorIs(t, err, dnssecbb.ErrSignatureMismatch)
	})

	t.Run("P-384 round trip", func(t *testing.T) {
		t.Parallel()
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)
		data := []byte("payload P-384")
		pub := ecdsaRawPub(key, 48)
		sig := ecdsaRawSig(t, key, 48, sha512.New384, data)
		require.NoError(t, dnssecbb.VerifyECDSAP384(data, pub, sig))
	})

	t.Run("P-384 tampered data", func(t *testing.T) {
		t.Parallel()
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)
		data := []byte("payload P-384")
		pub := ecdsaRawPub(key, 48)
		sig := ecdsaRawSig(t, key, 48, sha512.New384, data)
		err = dnssecbb.VerifyECDSAP384([]byte("tampered"), pub, sig)
		require.Error(t, err)
		require.ErrorIs(t, err, dnssecbb.ErrSignatureMismatch)
	})

	t.Run("wrong pubkey size", func(t *testing.T) {
		t.Parallel()
		err := dnssecbb.VerifyECDSAP256([]byte("d"), []byte{0x01, 0x02}, make([]byte, 64))
		require.Error(t, err)
		require.ErrorIs(t, err, dnssecbb.ErrSignatureMismatch)
	})

	t.Run("wrong signature size", func(t *testing.T) {
		t.Parallel()
		err := dnssecbb.VerifyECDSAP256([]byte("d"), make([]byte, 64), []byte{0x01})
		require.Error(t, err)
		require.ErrorIs(t, err, dnssecbb.ErrSignatureMismatch)
	})

	t.Run("VerifyECDSA direct call P-256", func(t *testing.T) {
		t.Parallel()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		data := []byte("direct call")
		pub := ecdsaRawPub(key, 32)
		sig := ecdsaRawSig(t, key, 32, sha256.New, data)
		require.NoError(t, dnssecbb.VerifyECDSA(elliptic.P256(), 32, sha256.New, data, pub, sig))
	})

	t.Run("invalid (R,S) bits don't verify", func(t *testing.T) {
		t.Parallel()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		pub := ecdsaRawPub(key, 32)
		// Random non-matching signature bytes: still 64 bytes, but garbage.
		bad := make([]byte, 64)
		for i := range bad {
			bad[i] = 0xab
		}
		err = dnssecbb.VerifyECDSAP256([]byte("d"), pub, bad)
		require.Error(t, err)
		require.ErrorIs(t, err, dnssecbb.ErrSignatureMismatch)
	})
}

func TestVerifyEd25519(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	data := []byte("ed25519 payload")
	sig := ed25519.Sign(priv, data)

	t.Run("verify", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, dnssecbb.VerifyEd25519(pub, data, sig))
	})

	t.Run("tampered data", func(t *testing.T) {
		t.Parallel()
		err := dnssecbb.VerifyEd25519(pub, []byte("tampered"), sig)
		require.Error(t, err)
		require.ErrorIs(t, err, dnssecbb.ErrSignatureMismatch)
	})

	t.Run("wrong pubkey size", func(t *testing.T) {
		t.Parallel()
		err := dnssecbb.VerifyEd25519([]byte{0x01, 0x02, 0x03}, data, sig)
		require.Error(t, err)
		require.ErrorIs(t, err, dnssecbb.ErrSignatureMismatch)
	})
}

func TestDigest(t *testing.T) {
	t.Parallel()

	data := []byte("digest input")

	t.Run("SHA-1", func(t *testing.T) {
		t.Parallel()
		got, err := dnssecbb.Digest(dnssecbb.DigestSHA1, data)
		require.NoError(t, err)
		want := sha1.Sum(data) //nolint:gosec
		require.Equal(t, want[:], got)
	})

	t.Run("SHA-256", func(t *testing.T) {
		t.Parallel()
		got, err := dnssecbb.Digest(dnssecbb.DigestSHA256, data)
		require.NoError(t, err)
		want := sha256.Sum256(data)
		require.Equal(t, want[:], got)
	})

	t.Run("SHA-384", func(t *testing.T) {
		t.Parallel()
		got, err := dnssecbb.Digest(dnssecbb.DigestSHA384, data)
		require.NoError(t, err)
		want := sha512.Sum384(data)
		require.Equal(t, want[:], got)
	})

	t.Run("unsupported digest type", func(t *testing.T) {
		t.Parallel()
		_, err := dnssecbb.Digest(99, data)
		require.Error(t, err)
		require.ErrorIs(t, err, dnssecbb.ErrUnsupportedAlgorithm)
	})
}

func TestSentinelErrorsDistinct(t *testing.T) {
	t.Parallel()
	require.NotNil(t, dnssecbb.ErrSignatureMismatch)
	require.NotNil(t, dnssecbb.ErrUnsupportedAlgorithm)
	require.False(t, errors.Is(dnssecbb.ErrSignatureMismatch, dnssecbb.ErrUnsupportedAlgorithm))
	require.False(t, errors.Is(dnssecbb.ErrUnsupportedAlgorithm, dnssecbb.ErrSignatureMismatch))
}
