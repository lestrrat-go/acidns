// Package sig0 implements RFC 2931 transaction-level message
// authentication via public-key cryptography. Unlike TSIG (RFC 8945)
// which uses an HMAC over a shared secret, SIG(0) uses asymmetric keys
// whose public half is normally published as a DNSKEY (or the legacy
// KEY) record at the signer's name.
//
// As with tsig, this package operates on raw msg bytes — call
// wire.Pack first, then Sign or Verify.
package sig0

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
	"fmt"
	"hash"
	"math/big"
	"time"

	"github.com/lestrrat-go/acidns/dnssec"
	"github.com/lestrrat-go/acidns/dnssec/dnssecbb"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
)

// sigType is the SIG RR type code (RFC 2535 §4.1, retained for SIG(0)).
const sigType uint16 = 24

// classANY is the class field of a SIG(0) RR per RFC 2931 §4.
const classANY uint16 = 255

// Errors.
var (
	ErrSIGMissing     = errors.New("sig0: no SIG(0) record in message")
	ErrBadTime        = errors.New("sig0: time outside validity window")
	ErrBadSignature   = errors.New("sig0: signature did not verify")
	ErrUnsupportedAlg = errors.New("sig0: unsupported algorithm")
	// ErrKeyTagMismatch is returned when the caller-supplied DNSKEY's
	// computed keyTag does not match the keyTag carried in the SIG(0)
	// RR. RFC 2535 §4.1 ties a SIG to the specific key that produced
	// it; refusing the mismatch prevents a caller juggling a key ring
	// from accidentally validating a message against a different
	// identity than the one the SIG claims.
	ErrKeyTagMismatch = errors.New("sig0: keytag mismatch between supplied DNSKEY and SIG(0) RR")
	// ErrReplay is returned by [VerifyWithReplay] when a verified
	// SIG(0) message duplicates one previously seen inside the replay
	// cache's retention window.
	ErrReplay = errors.New("sig0: message is a replay")
)

// Sign appends a SIG(0) RR to the additional section of msg and returns
// the new msg bytes. signFn produces the signature over the bytes that
// SIG(0) MUST cover (RFC 2931 §3.1) and is normally a closure around an
// *rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey.
func Sign(msg []byte, signer wire.Name, alg rdata.DNSSECAlgorithm, keyTag uint16,
	signFn func([]byte) ([]byte, error),
	now time.Time, validity time.Duration) ([]byte, error) {
	if len(msg) < 12 {
		return nil, fmt.Errorf("sig0: msg too short")
	}
	exp := now.Add(validity)
	// SIG(0) packs inception and expiration as 32-bit unsigned
	// seconds-since-epoch (RFC 2535 §4.1) — the format wraps in
	// 2106. Refuse to sign with timestamps outside that window so a
	// signer running on a far-future or pre-epoch clock surfaces an
	// error rather than silently producing a SIG whose validity
	// wraps around to 1970.
	if now.Unix() < 0 || exp.Unix() < 0 || now.Unix() > 0xFFFFFFFF || exp.Unix() > 0xFFFFFFFF {
		return nil, fmt.Errorf("sig0: timestamp out of 32-bit unsigned range (RFC 2535 §4.1 wrap-around)")
	}
	rdataNoSig := buildSIGRDataPrefix(alg, uint32(exp.Unix()), uint32(now.Unix()), keyTag, signer)

	signedData := append(append([]byte(nil), rdataNoSig...), msg...)
	sig, err := signFn(signedData)
	if err != nil {
		return nil, fmt.Errorf("sig0: sign callback: %w", err)
	}

	rdataFull := append(append([]byte(nil), rdataNoSig...), sig...)
	out := append(append([]byte(nil), msg...), appendSIGRR(nil, rdataFull)...)

	arcount := binary.BigEndian.Uint16(out[10:12])
	binary.BigEndian.PutUint16(out[10:12], arcount+1)
	return out, nil
}

// Verify confirms the trailing SIG(0) RR over msg using key — the
// DNSKEY published at the signer's name. The DNSKEY's algorithm,
// keyTag, and public-key bytes must match the SIG(0) RR's
// corresponding fields; a mismatch returns [ErrKeyTagMismatch] (or
// [ErrUnsupportedAlg] for the algorithm) before the cryptographic
// verification runs.
//
// The cryptographic check runs BEFORE the time-window check —
// matching tsig's order. Doing the time check first would let an
// unauthenticated peer probe the verifier's clock skew by submitting
// SIG(0) messages with varying inception/expiration and observing
// which return [ErrBadTime] vs [ErrBadSignature]; sig and time are
// independent failure modes from the attacker's perspective, so
// running the harder check first denies that timing oracle.
//
// SIG(0) does not by itself prevent message REPLAY within the
// validity window — see [VerifyWithReplay] for the replay-cache
// helper that pairs this primitive with a [ReplayCache].
//
// Returns the msg bytes without the SIG(0) RR.
func Verify(msg []byte, key rdata.DNSKEY, expectedSigner wire.Name, now time.Time) ([]byte, error) {
	body, _, err := verifyExtractSIG(msg, key, expectedSigner, now)
	return body, err
}

// verifyExtractSIG performs the full Verify pipeline and additionally
// returns the parsed SIG(0) so the replay-aware variant can key the
// cache on (signer, inception, signature).
func verifyExtractSIG(msg []byte, key rdata.DNSKEY, expectedSigner wire.Name, now time.Time) ([]byte, parsedSIG, error) {
	body, sig, err := stripSIG(msg)
	if err != nil {
		return nil, parsedSIG{}, err
	}
	if !sig.signer.Equal(expectedSigner) {
		return nil, parsedSIG{}, fmt.Errorf("sig0: signer mismatch: got %s", sig.signer)
	}
	if key.Algorithm() != sig.algorithm {
		return nil, parsedSIG{}, fmt.Errorf("%w: alg mismatch", ErrUnsupportedAlg)
	}
	// Share the DNSSEC package's explicit deny-list. The switch in
	// verifySignature only handles modern algorithms, but adding the
	// shared deny-list here makes the rejection intentional and stops
	// a future maintainer from silently weakening SIG(0) by extending
	// the switch with a deprecated algorithm.
	if dnssec.IsRejectedAlgorithm(sig.algorithm) {
		return nil, parsedSIG{}, fmt.Errorf("%w: deprecated algorithm %d", ErrUnsupportedAlg, sig.algorithm)
	}
	if dnssec.KeyTag(key) != sig.keyTag {
		return nil, parsedSIG{}, fmt.Errorf("%w: SIG keytag %d, supplied DNSKEY %d",
			ErrKeyTagMismatch, sig.keyTag, dnssec.KeyTag(key))
	}

	rdataNoSig := buildSIGRDataPrefix(key.Algorithm(), sig.expiration, sig.inception, sig.keyTag, sig.signer)
	signedData := append(append([]byte(nil), rdataNoSig...), body...)

	if err := verifySignature(key.Algorithm(), key.PublicKey(), signedData, sig.signature); err != nil {
		return nil, parsedSIG{}, err
	}
	// RFC 2931 §3.1 / RFC 4034 §3.1.5: inception/expiration are
	// 32-bit absolute seconds-since-epoch interpreted under RFC 1982
	// serial-number arithmetic (mod 2³²). The naive int64 comparison
	// wraps incorrectly past 2106-02-07; use the canonical
	// signed-wraparound predicate instead.
	nowU := uint32(now.Unix())
	if sig0SerialLT(sig.expiration, nowU) || sig0SerialLT(nowU, sig.inception) {
		return nil, parsedSIG{}, ErrBadTime
	}
	return body, sig, nil
}

// VerifyWithReplay performs Verify and, on success, consults cache to
// reject re-played messages. RFC 2931 leaves replay defence to the
// application; UPDATE / NOTIFY / any other side-effecting opcode that
// flows over a SIG(0)-protected channel SHOULD use this variant.
//
// Returns [ErrReplay] when the (signer, inception, signature) tuple
// has already been recorded inside the cache's retention window.
// Cache.Seen is consulted only after the cryptographic verification
// passes, so an attacker cannot pollute the cache by replaying random
// junk.
func VerifyWithReplay(msg []byte, key rdata.DNSKEY, expectedSigner wire.Name, now time.Time, cache ReplayCache) ([]byte, error) {
	body, sig, err := verifyExtractSIG(msg, key, expectedSigner, now)
	if err != nil {
		return nil, err
	}
	if cache != nil {
		incept := time.Unix(int64(sig.inception), 0)
		if cache.Seen(sig.signer, incept, sig.signature) {
			return nil, ErrReplay
		}
	}
	return body, nil
}

// sig0SerialLT is RFC 1982 §3.2 mod-2³² "less than" on uint32 — see
// the same predicate in dnssec/validator/validatorbb. Inlined here so
// the sig0 package does not import the validator package.
func sig0SerialLT(a, b uint32) bool { return int32(a-b) < 0 }

// buildSIGRDataPrefix builds the part of the SIG(0) rdata that comes
// before the signature field — exactly the bytes signed/verified.
func buildSIGRDataPrefix(alg rdata.DNSSECAlgorithm, expiration, inception uint32, keyTag uint16, signer wire.Name) []byte {
	var buf []byte
	// type covered = 0 for SIG(0)
	buf = binary.BigEndian.AppendUint16(buf, 0)
	buf = append(buf, uint8(alg))
	buf = append(buf, 0)                        // labels = 0
	buf = binary.BigEndian.AppendUint32(buf, 0) // original TTL = 0
	buf = binary.BigEndian.AppendUint32(buf, expiration)
	buf = binary.BigEndian.AppendUint32(buf, inception)
	buf = binary.BigEndian.AppendUint16(buf, keyTag)
	buf = append(buf, signer.AppendWire(nil)...)
	return buf
}

// appendSIGRR builds the SIG(0) RR's msg form: owner=root, type=SIG,
// class=ANY, TTL=0, rdlen, rdata.
func appendSIGRR(buf []byte, rdataBytes []byte) []byte {
	buf = append(buf, 0) // owner = root
	buf = binary.BigEndian.AppendUint16(buf, sigType)
	buf = binary.BigEndian.AppendUint16(buf, classANY)
	buf = binary.BigEndian.AppendUint32(buf, 0) // TTL = 0
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(rdataBytes)))
	buf = append(buf, rdataBytes...)
	return buf
}

type parsedSIG struct {
	algorithm  rdata.DNSSECAlgorithm
	expiration uint32
	inception  uint32
	keyTag     uint16
	signer     wire.Name
	signature  []byte
}

func stripSIG(msg []byte) ([]byte, parsedSIG, error) {
	if len(msg) < 12 {
		return nil, parsedSIG{}, fmt.Errorf("sig0: msg too short")
	}
	arcount := binary.BigEndian.Uint16(msg[10:12])
	if arcount == 0 {
		return nil, parsedSIG{}, ErrSIGMissing
	}

	last, err := findLastRROffset(msg)
	if err != nil {
		return nil, parsedSIG{}, err
	}
	owner, off, err := wire.DecodeName(msg, last)
	if err != nil {
		return nil, parsedSIG{}, fmt.Errorf("sig0: parse owner: %w", err)
	}
	if !owner.IsRoot() {
		// RFC 2931 §4 fixes the owner of a SIG(0) RR at the root
		// domain. The owner is not in the signed bytes so a non-root
		// owner does not affect signature validity, but accepting it
		// weakens the package's fail-closed posture.
		return nil, parsedSIG{}, ErrSIGMissing
	}
	if off+10 > len(msg) {
		return nil, parsedSIG{}, fmt.Errorf("sig0: truncated header")
	}
	t := binary.BigEndian.Uint16(msg[off : off+2])
	if t != sigType {
		return nil, parsedSIG{}, ErrSIGMissing
	}
	cls := binary.BigEndian.Uint16(msg[off+2 : off+4])
	if cls != classANY {
		// RFC 2931 §4 fixes the SIG(0) RR class to ANY (255).
		return nil, parsedSIG{}, ErrSIGMissing
	}
	rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
	rdataStart := off + 10
	rdataEnd := rdataStart + rdlen
	if rdataEnd > len(msg) {
		return nil, parsedSIG{}, fmt.Errorf("sig0: truncated rdata")
	}

	cur := rdataStart
	if cur+18 > rdataEnd {
		return nil, parsedSIG{}, fmt.Errorf("sig0: truncated SIG header")
	}
	// type covered (2) + algorithm(1) + labels(1) + origTTL(4) + sigExp(4) + sigInc(4) + keyTag(2) = 18
	cur += 2 // skip type covered
	alg := rdata.DNSSECAlgorithm(msg[cur])
	cur++
	cur++    // labels
	cur += 4 // orig TTL
	expiration := binary.BigEndian.Uint32(msg[cur:])
	cur += 4
	inception := binary.BigEndian.Uint32(msg[cur:])
	cur += 4
	keyTag := binary.BigEndian.Uint16(msg[cur:])
	cur += 2

	signer, sigStart, err := wire.DecodeName(msg, cur)
	if err != nil {
		return nil, parsedSIG{}, fmt.Errorf("sig0: parse signer: %w", err)
	}
	if sigStart > rdataEnd {
		return nil, parsedSIG{}, fmt.Errorf("sig0: signer overruns rdata")
	}
	signature := append([]byte(nil), msg[sigStart:rdataEnd]...)

	body := append([]byte(nil), msg[:last]...)
	binary.BigEndian.PutUint16(body[10:12], arcount-1)
	return body, parsedSIG{
		algorithm: alg, expiration: expiration, inception: inception,
		keyTag: keyTag, signer: signer, signature: signature,
	}, nil
}

func findLastRROffset(msg []byte) (int, error) {
	qdcount := int(binary.BigEndian.Uint16(msg[4:6]))
	ancount := int(binary.BigEndian.Uint16(msg[6:8]))
	nscount := int(binary.BigEndian.Uint16(msg[8:10]))
	arcount := int(binary.BigEndian.Uint16(msg[10:12]))
	totalRR := ancount + nscount + arcount
	off := 12
	for range qdcount {
		_, next, err := wire.DecodeName(msg, off)
		if err != nil {
			return 0, err
		}
		off = next + 4
		if off > len(msg) {
			return 0, fmt.Errorf("sig0: truncated question")
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
			return 0, fmt.Errorf("sig0: truncated rr header")
		}
		rdlen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
		off = next + 10 + rdlen
		if off > len(msg) {
			return 0, fmt.Errorf("sig0: truncated rr body")
		}
	}
	return last, nil
}

// verifySignature dispatches to the algorithm-specific verifier. Algorithm
// implementations match dnssec/verify.go.
func verifySignature(alg rdata.DNSSECAlgorithm, pubkeyWire, data, sig []byte) error {
	switch alg {
	case rdata.AlgRSASHA256:
		pub, err := parseRSAPublic(pubkeyWire)
		if err != nil {
			return err
		}
		h := sha256.Sum256(data)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig); err != nil {
			return fmt.Errorf("%w: %w", ErrBadSignature, err)
		}
		return nil
	case rdata.AlgRSASHA512:
		pub, err := parseRSAPublic(pubkeyWire)
		if err != nil {
			return err
		}
		h := sha512.Sum512(data)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA512, h[:], sig); err != nil {
			return fmt.Errorf("%w: %w", ErrBadSignature, err)
		}
		return nil
	case rdata.AlgECDSAP256SHA256:
		return verifyECDSA(elliptic.P256(), 32, sha256.New, data, pubkeyWire, sig)
	case rdata.AlgECDSAP384SHA384:
		return verifyECDSA(elliptic.P384(), 48, sha512.New384, data, pubkeyWire, sig)
	case rdata.AlgED25519:
		if len(pubkeyWire) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: ed25519 pubkey wrong size", ErrBadSignature)
		}
		if !ed25519.Verify(ed25519.PublicKey(pubkeyWire), data, sig) {
			return ErrBadSignature
		}
		return nil
	default:
		return fmt.Errorf("%w: %d", ErrUnsupportedAlg, alg)
	}
}

// parseRSAPublic delegates to dnssecbb.ParseRSAPublic so SIG(0) RSA
// keys inherit the same modulus floor (RFC 8624 §3.1) and ceiling
// the DNSSEC validator already enforces. A separate parser would let
// a SIG(0) signer ship a sub-1024-bit key whose signatures verify
// without any cryptographic strength.
//
// Wrapping the error tags it with the sig0 package so callers
// continue to see "sig0: ..." in their logs.
func parseRSAPublic(b []byte) (*rsa.PublicKey, error) {
	pk, err := dnssecbb.ParseRSAPublic(b)
	if err != nil {
		return nil, fmt.Errorf("sig0: %w", err)
	}
	return pk, nil
}

func verifyECDSA(curve elliptic.Curve, sz int, h func() hash.Hash, data, pub, sig []byte) error {
	if len(pub) != 2*sz {
		return fmt.Errorf("%w: ecdsa pubkey wrong size", ErrBadSignature)
	}
	if len(sig) != 2*sz {
		return fmt.Errorf("%w: ecdsa signature wrong size", ErrBadSignature)
	}
	x := new(big.Int).SetBytes(pub[:sz])
	y := new(big.Int).SetBytes(pub[sz:])
	r := new(big.Int).SetBytes(sig[:sz])
	s := new(big.Int).SetBytes(sig[sz:])
	pubKey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	hh := h()
	hh.Write(data)
	if !ecdsa.Verify(pubKey, hh.Sum(nil), r, s) {
		return ErrBadSignature
	}
	return nil
}

// sentinel use of crypto/rand to keep the signing helpers concrete in
// callers' minds — sig0.Sign callbacks for RSA/ECDSA usually want
// rand.Reader.
var _ = rand.Reader
