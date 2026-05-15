package examples_test

import (
	"crypto/sha1" //nolint:gosec // this example demonstrates SHA-1 DS interop
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/lestrrat-go/acidns/dnssec"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
)

// Example_dnssec_verify_ds_sha1 demonstrates the SHA-1 DS escape hatch.
// RFC 8624 §3.3 marks SHA-1 DS digests as NOT RECOMMENDED; the default
// [dnssec.VerifyDS] refuses them. [dnssec.VerifyDSWithSHA1] exists for
// the rare case of authenticating a legacy zone still publishing SHA-1
// DS only — during a parent-zone rollover from SHA-1 to SHA-256/384.
//
// Prefer [dnssec.VerifyDS] for any new code. Pinning a chain through
// the SHA-1 variant means accepting that a SHA-1 collision attack
// against the DS would let an attacker substitute a forged DNSKEY
// undetected.
func Example_dnssec_verify_ds_sha1() {
	// A toy zone-signing key.
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i ^ 0x33)
	}
	key, err := rdata.NewDNSKEY(257, 3, rdata.AlgED25519, pub)
	if err != nil {
		fmt.Println("dnskey:", err)
		return
	}
	owner := wire.MustParseName("legacy.example.")

	// Build the SHA-1 digest the parent zone would publish over
	// (canonical owner || dnskey rdata).
	var data []byte
	data = append(data, owner.AppendWire(nil)...)
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint16(hdr[0:], key.Flags())
	hdr[2] = key.Protocol()
	hdr[3] = uint8(key.Algorithm())
	data = append(data, hdr...)
	data = append(data, pub...)
	digest := sha1.Sum(data)

	ds, err := rdata.NewDS(dnssec.KeyTag(key), key.Algorithm(), rdata.DigestSHA1, digest[:])
	if err != nil {
		fmt.Println("ds:", err)
		return
	}

	// Default: SHA-1 DS is refused.
	if err := dnssec.VerifyDS(owner, ds, key); errors.Is(err, dnssec.ErrUnsupportedAlgorithm) {
		fmt.Println("VerifyDS:           refused (SHA-1 NOT RECOMMENDED)")
	}

	// Opt-in: SHA-1 DS is accepted.
	if err := dnssec.VerifyDSWithSHA1(owner, ds, key); err == nil {
		fmt.Println("VerifyDSWithSHA1:   accepted")
	}

	// OUTPUT:
	// VerifyDS:           refused (SHA-1 NOT RECOMMENDED)
	// VerifyDSWithSHA1:   accepted
}
