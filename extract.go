package acidns

import (
	"context"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// ResolveAs queries r for the RR type that corresponds to T (inferred from
// T's zero value) and returns every matching rdata asserted to T.
//
// T is constrained to rdata.Typed, so ResolveAs[rdata.Unknown] is a compile
// error — Unknown has no inherent rrtype. To query for a specific RR type
// code with no expectation that the response will decode to a typed rdata,
// use Resolver.Resolve directly and Extract[rdata.Unknown] over the
// returned records.
func ResolveAs[T rdata.Typed](ctx context.Context, r Resolver, name wire.Name) ([]T, error) {
	var zero T
	ans, err := r.Resolve(ctx, name, zero.Type())
	if err != nil {
		return nil, err
	}
	return Extract[T](ans.Records()), nil
}

// Extract returns every rdata in records that asserts to T. The RR type
// filter is inferred from T's zero value. Two special cases:
//
//   - Extract[rdata.Unknown] returns every record whose rdata did not
//     decode to a typed payload (Unknown carries its rrtype per-instance).
//   - Extract[rdata.RData] is the degenerate "any rdata" form. The RData
//     interface itself has no inherent rrtype, so calling Type() on the
//     nil zero would panic; the call is skipped and every record is
//     returned that asserts to T (which, for the umbrella interface, is
//     every record).
func Extract[T rdata.RData](records []wire.Record) []T {
	var zero T
	_, isUnknown := any(zero).(rdata.Unknown)
	// any(zero) == nil iff T is itself the rdata.RData interface (or any
	// other interface type that embeds it) — concrete typed rdata zero
	// values box to a non-nil any. Skip the rrtype filter in that case.
	useTypeFilter := !isUnknown && any(zero) != nil
	var t rrtype.Type
	if useTypeFilter {
		t = zero.Type()
	}

	out := make([]T, 0, len(records))
	for _, rec := range records {
		if useTypeFilter && rec.Type() != t {
			continue
		}
		if v, ok := rec.RData().(T); ok {
			out = append(out, v)
		}
	}
	return out
}
