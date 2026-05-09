package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/acidns/dnssec/validator"
	"github.com/lestrrat-go/acidns/wire"
)

func Example_validator_nta() {
	// NTAStore is a runtime-mutable Negative Trust Anchor registry. Add
	// names whose subtree should bypass validation — useful during a TLD
	// outage (cf. the May-2025 .de incident). Each entry expires after the
	// supplied TTL (RFC 7646 §3 caps NTAs at one week so a forgotten entry
	// cannot become a permanent validation hole). A zero TTL falls back to
	// validator.DefaultNTATTL (24h).
	store := validator.NewNTAStore()
	store.Add(wire.MustParseName("de"), 0)

	fmt.Println("de:", store.Covers(wire.MustParseName("de")))
	fmt.Println("denic.de:", store.Covers(wire.MustParseName("denic.de")))
	fmt.Println("example.com:", store.Covers(wire.MustParseName("example.com")))

	// Wire the store into a Validator; ValidateRRset short-circuits to
	// Indeterminate (and skips signature checks) for any name covered by
	// the store.
	v, err := validator.New(validator.WithValidatorNTAStore(store))
	if err != nil {
		fmt.Println("validator:", err)
		return
	}
	res, err := v.VerifyDelegation(wire.MustParseName("denic.de"), nil, nil) //nolint:govet // intentional shadow
	fmt.Println("result:", res, "err:", err == nil)

	// OUTPUT:
	// de: true
	// denic.de: true
	// example.com: false
	// result: indeterminate err: true
}
