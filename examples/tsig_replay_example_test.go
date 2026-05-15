package examples_test

import (
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/acidns/tsig"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// verifyReplay wraps tsig.VerifyWithReplay so the example only deals
// with the error half of the result tuple — the example's narrative is
// "did this verify or not?" rather than "what did the call return?".
func verifyReplay(msg []byte, key tsig.Key, cache tsig.ReplayCache, now time.Time, fudge time.Duration) error {
	_, _, _, err := tsig.VerifyWithReplay(msg, key, cache, now, fudge) //nolint:dogsled // only error is needed here
	return err
}

// Example_tsig_replay shows the canonical "verify then check replay"
// pattern for TSIG-signed messages. RFC 8945 §5.2.3 leaves replay
// defence to the application; the [tsig.VerifyWithReplay] wrapper
// closes the easy-to-forget two-step pattern that leaves the receiver
// open to fudge-window replays.
func Example_tsig_replay() {
	key, err := tsig.NewKey(
		wire.MustParseName("example-key"), tsig.HMACSHA256,
		[]byte("a-shared-secret-of-at-least-256-bits"),
	)
	if err != nil {
		fmt.Println("key:", err)
		return
	}

	q, _ := wire.NewMessageBuilder().
		ID(0xc0de).
		Question(wire.NewQuestion(wire.MustParseName("example.com"), rrtype.A)).
		Build()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	signed, err := tsig.SignMessage(q, key, now, 5*time.Minute)
	if err != nil {
		fmt.Println("sign:", err)
		return
	}

	// One shared cache per server process. Safe for concurrent use
	// across per-request handler goroutines.
	cache := tsig.NewMemoryReplayCache(
		tsig.WithReplayWindow(5 * time.Minute),
	)

	// First receipt of the envelope: fresh.
	if err := verifyReplay(signed, key, cache, now, 5*time.Minute); err != nil {
		fmt.Println("first verify:", err)
		return
	}
	fmt.Println("first verify: ok")

	// A replay of the same bytes within the cache window is rejected
	// with ErrReplay — distinct from a generic VerifyMAC failure.
	if errors.Is(verifyReplay(signed, key, cache, now, 5*time.Minute), tsig.ErrReplay) {
		fmt.Println("second verify: replay detected")
	}

	// OUTPUT:
	// first verify: ok
	// second verify: replay detected
}
