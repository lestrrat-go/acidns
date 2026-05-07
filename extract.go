package acidns

import (
	"context"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
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
// filter is inferred from T's zero value. Extract[rdata.Unknown] is a
// special case: Unknown carries its rrtype in a per-instance field, so the
// type filter is skipped and Extract returns every record whose rdata
// could not be decoded into a typed payload.
func Extract[T rdata.RData](records []wire.Record) []T {
	var zero T
	t := zero.Type()
	_, isUnknown := any(zero).(rdata.Unknown)

	out := make([]T, 0, len(records))
	for _, rec := range records {
		if !isUnknown && rec.Type() != t {
			continue
		}
		if v, ok := rec.RData().(T); ok {
			out = append(out, v)
		}
	}
	return out
}
