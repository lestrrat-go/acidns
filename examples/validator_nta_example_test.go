package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/lestrrat-go/acidns/dnssec/validator"
)

func Example_validator_nta() {
	// NTAStore is a runtime-mutable Negative Trust Anchor registry. Add
	// names whose subtree should bypass validation — useful during a TLD
	// outage (cf. the May-2025 .de incident). Covers reports whether a
	// name falls under any registered NTA.
	store := validator.NewNTAStore()
	store.Add(dnsname.MustParse("de"))

	fmt.Println(store.Covers(dnsname.MustParse("de")))
	fmt.Println(store.Covers(dnsname.MustParse("denic.de")))
	fmt.Println(store.Covers(dnsname.MustParse("example.com")))

	// Wire the store into a Validator; ValidateRRset short-circuits to
	// Indeterminate (and skips signature checks) for any name covered by
	// the store.
	v := validator.New(validator.Options{NTAs: store})
	res, err := v.VerifyDelegation(dnsname.MustParse("denic.de"), nil, nil)
	fmt.Println("result:", res, "err:", err == nil)

	// OUTPUT:
	// true
	// true
	// false
	// result: indeterminate err: true
}
