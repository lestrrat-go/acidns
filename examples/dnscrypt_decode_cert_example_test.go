package examples_test

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/lestrrat-go/acidns/dnscrypt"
)

func Example_dnscrypt_decode_cert() {
	// Provider long-term Ed25519 keypair. Seeded from a fixed byte string
	// so the keys (and therefore the signature) are deterministic.
	seed := []byte("acidns-dnscrypt-example-seed-32!")
	providerPriv := ed25519.NewKeyFromSeed(seed)
	providerPub := providerPriv.Public().(ed25519.PublicKey)

	// Resolver short-term X25519 keypair, also seeded.
	var resolverSK [32]byte
	copy(resolverSK[:], []byte("acidns-resolver-sk-32-bytes-seed"))
	resolverPKBytes, err := curve25519.X25519(resolverSK[:], curve25519.Basepoint)
	if err != nil {
		fmt.Println("x25519:", err)
		return
	}
	var resolverPK [32]byte
	copy(resolverPK[:], resolverPKBytes)

	cert := dnscrypt.NewCert(
		dnscrypt.ESVersion2,
		0,
		resolverPK,
		[8]byte{'a', 'c', 'i', 'd', 'n', 's', 'c', 't'},
		1,
		time.Unix(1_700_000_000, 0).UTC(),
		time.Unix(1_900_000_000, 0).UTC(),
	)
	dnscrypt.SignCert(cert, providerPriv)

	// Round-trip through wire form.
	wireForm := dnscrypt.EncodeCert(cert)
	parsed, err := dnscrypt.ParseCert(wireForm)
	if err != nil {
		fmt.Println("parse:", err)
		return
	}

	now := time.Unix(1_800_000_000, 0).UTC()
	if err := parsed.Verify(providerPub, now); err != nil {
		fmt.Println("verify:", err)
		return
	}

	cm := parsed.ClientMagic()
	fmt.Println("wire size:", len(wireForm))
	fmt.Println("es version:", parsed.ESVersion())
	fmt.Println("client magic:", string(cm[:]))
	fmt.Println("serial:", parsed.Serial())
	fmt.Println("verified at fixed now: ok")

	// OUTPUT:
	// wire size: 124
	// es version: 2
	// client magic: acidnsct
	// serial: 1
	// verified at fixed now: ok
}
