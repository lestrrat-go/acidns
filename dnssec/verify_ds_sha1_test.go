package dnssec_test

import (
	"crypto/sha1"
	"encoding/binary"
	"testing"

	"github.com/lestrrat-go/acidns/dnssec"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/stretchr/testify/require"
)

// mkSHA1DS builds a DS RR carrying a legitimate SHA-1 digest over
// (owner || dnskey rdata). Helper for both the rejection-by-default and
// opt-in paths so the two tests stay in sync.
func mkSHA1DS(t *testing.T, owner wire.Name, key rdata.DNSKEY, pub []byte) rdata.DS {
	t.Helper()
	var data []byte
	data = append(data, owner.AppendWire(nil)...)
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint16(hdr[0:], key.Flags())
	hdr[2] = key.Protocol()
	hdr[3] = uint8(key.Algorithm())
	data = append(data, hdr...)
	data = append(data, pub...)
	digest := sha1.Sum(data) //nolint:gosec // SHA-1 is what this test exercises
	ds, err := rdata.NewDS(dnssec.KeyTag(key), key.Algorithm(), rdata.DigestSHA1, digest[:])
	require.NoError(t, err)
	return ds
}

// TestVerifyDSRejectsSHA1ByDefault pins the security posture: even a
// legitimate SHA-1 DS (one whose digest does match the key) is refused
// by [dnssec.VerifyDS]. The rejection surfaces as ErrUnsupportedAlgorithm
// so callers can match it.
func TestVerifyDSRejectsSHA1ByDefault(t *testing.T) {
	t.Parallel()
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i ^ 0x33)
	}
	key, err := rdata.NewDNSKEY(257, 3, rdata.AlgED25519, pub)
	require.NoError(t, err)
	owner := wire.MustParseName("legacy.example.")
	ds := mkSHA1DS(t, owner, key, pub)

	err = dnssec.VerifyDS(owner, ds, key)
	require.ErrorIs(t, err, dnssec.ErrUnsupportedAlgorithm,
		"the default entry point must refuse SHA-1 DS digests")
}

// TestVerifyDSWithSHA1AcceptsLegitimateDigest is the legacy-zone
// rollover escape hatch. With the SHA-1-permissive entry point, a
// genuine SHA-1 digest over (owner || dnskey) verifies.
func TestVerifyDSWithSHA1AcceptsLegitimateDigest(t *testing.T) {
	t.Parallel()
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i ^ 0x33)
	}
	key, err := rdata.NewDNSKEY(257, 3, rdata.AlgED25519, pub)
	require.NoError(t, err)
	owner := wire.MustParseName("legacy.example.")
	ds := mkSHA1DS(t, owner, key, pub)

	require.NoError(t, dnssec.VerifyDSWithSHA1(owner, ds, key))
}

// TestVerifyDSWithSHA1RejectsTamperedDigest confirms the SHA-1 path
// still catches forgery — opting in to SHA-1 doesn't disable the digest
// check, it only loosens the algorithm gate.
func TestVerifyDSWithSHA1RejectsTamperedDigest(t *testing.T) {
	t.Parallel()
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i ^ 0x77)
	}
	key, err := rdata.NewDNSKEY(257, 3, rdata.AlgED25519, pub)
	require.NoError(t, err)
	owner := wire.MustParseName("legacy.example.")
	good := mkSHA1DS(t, owner, key, pub)

	tampered := append([]byte(nil), good.Digest()...)
	tampered[0] ^= 0xff
	dsBad, err := rdata.NewDS(dnssec.KeyTag(key), key.Algorithm(), rdata.DigestSHA1, tampered)
	require.NoError(t, err)

	require.ErrorIs(t, dnssec.VerifyDSWithSHA1(owner, dsBad, key), dnssec.ErrSignatureMismatch)
}
