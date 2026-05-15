package examples_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/acidns/dnssec"
	"github.com/lestrrat-go/acidns/sig0"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// Example_sig0_replay shows how to pair sig0.Verify with a replay cache.
// SIG(0) by itself only proves a message was signed within its validity
// window; an attacker who captures a signed UPDATE / NOTIFY can replay
// it until that window elapses. Production servers handling
// side-effecting opcodes plug a [sig0.ReplayCache] into
// [sig0.VerifyWithReplay] to reject duplicates.
func Example_sig0_replay() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("keygen:", err)
		return
	}
	key, err := rdata.NewDNSKEY(257, 3, rdata.AlgED25519, pub)
	if err != nil {
		fmt.Println("dnskey:", err)
		return
	}

	q, _ := wire.NewMessageBuilder().
		ID(0xface).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()
	msg, _ := wire.Pack(q)

	signer := wire.MustParseName("primary.example.")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	signed, err := sig0.Sign(msg, signer, rdata.AlgED25519, dnssec.KeyTag(key),
		func(payload []byte) ([]byte, error) { return ed25519.Sign(priv, payload), nil },
		now, time.Hour)
	if err != nil {
		fmt.Println("sign:", err)
		return
	}

	// The cache lives for the lifetime of the server process. A single
	// shared *MemoryReplayCache is safe for concurrent use across many
	// handler goroutines.
	cache := sig0.NewMemoryReplayCache(
		sig0.WithReplayWindow(5 * time.Minute),
	)

	// First verification: the message is fresh — verify succeeds.
	if _, err := sig0.VerifyWithReplay(signed, key, signer, now, cache); err != nil {
		fmt.Println("first verify:", err)
		return
	}
	fmt.Println("first verify: ok")

	// Second verification of the same bytes: the cache catches the
	// duplicate. Callers match on sig0.ErrReplay to distinguish a
	// replay from a genuine verification failure.
	_, err = sig0.VerifyWithReplay(signed, key, signer, now, cache)
	if errors.Is(err, sig0.ErrReplay) {
		fmt.Println("second verify: replay detected")
	}

	// OUTPUT:
	// first verify: ok
	// second verify: replay detected
}
