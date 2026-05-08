package acidns

import (
	"context"
	"net/netip"
	"strings"
	"sync"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// LookupHost dispatches A and AAAA queries for host concurrently and returns
// every address either query produced. If r satisfies SearchLister, the host
// string is expanded against the search list using its Ndots threshold;
// trailing-dot names bypass expansion.
//
// A non-NoError RCODE on any individual sub-query is treated as a soft fail:
// LookupHost continues to the next candidate name. Only when no candidate
// produces addresses does the most recent error surface to the caller.
func LookupHost(ctx context.Context, r Resolver, host string) ([]netip.Addr, error) {
	candidates, err := candidateNames(r, host)
	if err != nil {
		return nil, err
	}
	var firstErr error
	for _, name := range candidates {
		addrs, err := lookupHostAbsolute(ctx, r, name)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if len(addrs) > 0 {
			return addrs, nil
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, nil
}

// candidateNames builds the ordered list of FQDNs to attempt for a LookupHost
// call. When r does not satisfy SearchLister (or the search list is empty),
// only the parsed host is returned.
func candidateNames(r Resolver, host string) ([]wire.Name, error) {
	absolute := strings.HasSuffix(host, ".")
	base, err := wire.ParseName(host)
	if err != nil {
		return nil, err
	}
	sl, ok := r.(SearchLister)
	if absolute || !ok || len(sl.SearchList()) == 0 {
		return []wire.Name{base}, nil
	}
	dots := strings.Count(strings.TrimSuffix(host, "."), ".")
	list := sl.SearchList()
	suffixed := make([]wire.Name, 0, len(list))
	for _, s := range list {
		n, err := wire.ParseName(host + "." + s.String())
		if err != nil {
			continue
		}
		suffixed = append(suffixed, n)
	}
	if dots >= sl.Ndots() {
		return append([]wire.Name{base}, suffixed...), nil
	}
	return append(suffixed, base), nil
}

func lookupHostAbsolute(ctx context.Context, r Resolver, name wire.Name) ([]netip.Addr, error) {
	type result struct {
		addrs []netip.Addr
		err   error
	}
	ch := make(chan result, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	dispatch := func(t rrtype.Type) {
		defer wg.Done()
		ans, err := r.Resolve(ctx, name, t)
		if err != nil {
			ch <- result{err: err}
			return
		}
		out := make([]netip.Addr, 0, len(ans.Records()))
		for _, rec := range ans.Records() {
			if a, ok := wire.RDataAs[rdata.A](rec); ok {
				out = append(out, a.Addr())
				continue
			}
			if aaaa, ok := wire.RDataAs[rdata.AAAA](rec); ok {
				out = append(out, aaaa.Addr())
			}
		}
		ch <- result{addrs: out}
	}
	go dispatch(rrtype.A)
	go dispatch(rrtype.AAAA)
	wg.Wait()
	close(ch)

	var addrs []netip.Addr
	var firstErr error
	for got := range ch {
		if got.err != nil && firstErr == nil {
			firstErr = got.err
			continue
		}
		addrs = append(addrs, got.addrs...)
	}
	if len(addrs) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return addrs, nil
}
