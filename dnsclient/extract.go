package dnsclient

import (
	"context"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// ResolveAs queries r for (name, t) and returns the rdata of every matching
// record asserted to T. Equivalent to:
//
//	ans, err := r.Resolve(ctx, name, t)
//	if err != nil { return nil, err }
//	return Extract[T](ans.Records(), t), nil
//
// The explicit rrtype.Type argument is required because rdata interface
// satisfaction is structural — see the rdata-dispatch convention. Callers
// MUST pass the rrtype.Type that corresponds to T (e.g. rdata.MX paired with
// rrtype.MX).
func ResolveAs[T rdata.RData](ctx context.Context, r Resolver, name wire.Name, t rrtype.Type) ([]T, error) {
	ans, err := r.Resolve(ctx, name, t)
	if err != nil {
		return nil, err
	}
	return Extract[T](ans.Records(), t), nil
}

// Extract returns every rdata in records whose owner type is t, asserted to
// T. Records whose Type() does not match t are skipped — the Type() check
// MUST come before the assertion because rdata.A and rdata.AAAA share a
// method set, rdata.CNAME and rdata.SVCB share Target(), etc.
func Extract[T rdata.RData](records []wire.Record, t rrtype.Type) []T {
	out := make([]T, 0, len(records))
	for _, rec := range records {
		if rec.Type() != t {
			continue
		}
		if v, ok := rec.RData().(T); ok {
			out = append(out, v)
		}
	}
	return out
}
