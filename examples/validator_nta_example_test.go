package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/acidns/dnssec/validator"
	"github.com/lestrrat-go/acidns/wire"
)

func Example_validator_nta() {
	// NTAStore is a runtime-mutable Negative Trust Anchor registry. Add
	// names whose subtree should bypass validation — useful during a TLD
	// outage (cf. the May-2025 .de incident). Covers reports whether a
	// name falls under any registered NTA.
	store := validator.NewNTAStore()
	store.Add(wire.MustParseName("de"))

	fmt.Println(store.Covers(wire.MustParseName("de")))
	fmt.Println(store.Covers(wire.MustParseName("denic.de")))
	fmt.Println(store.Covers(wire.MustParseName("example.com")))

	// Wire the store into a Validator; ValidateRRset short-circuits to
	// Indeterminate (and skips signature checks) for any name covered by
	// the store.
	v := validator.New(validator.Options{NTAs: store})
	res, err := v.VerifyDelegation(wire.MustParseName("denic.de"), nil, nil)
	fmt.Println("result:", res, "err:", err == nil)

	// OUTPUT:
	// true
	// true
	// false
	// result: indeterminate err: true
}
