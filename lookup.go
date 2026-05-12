package acidns

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/option/v3"
)

// LookupOption configures a call to [LookupHost].
type LookupOption interface {
	option.Interface
	lookupOption()
}

type lookupOption struct{ option.Interface }

func (lookupOption) lookupOption() {}

type identLookupSearchList struct{}

type searchListSpec struct {
	suffixes []wire.Name
	ndots    int
}

// WithLookupSearchList enables short-name expansion in [LookupHost].
// For each call, ndots controls when the bare host is tried first
// versus last (matching standard stub-resolver behaviour). Without
// this option [LookupHost] queries the host as given, with no
// expansion — the safe default.
//
// SECURITY: see the doc comment on [LookupHost] for the wpad-leak
// scenario; this option is the explicit opt-in that enables that
// behaviour. Use [SearchListDefaults] for the common case of "expand
// against this resolver's configured list".
func WithLookupSearchList(suffixes []wire.Name, ndots int) LookupOption {
	cp := append([]wire.Name(nil), suffixes...)
	return lookupOption{option.New(identLookupSearchList{}, searchListSpec{suffixes: cp, ndots: ndots})}
}

// SearchListDefaults returns a [LookupOption] sourced from r if r
// implements [SearchListProvider]. Equivalent to
// `WithLookupSearchList(r.SearchList(), r.Ndots())`. A resolver that
// does not satisfy [SearchListProvider] contributes a no-op option;
// nothing is silently dropped because the caller already declared
// intent by invoking this helper.
func SearchListDefaults(r Resolver) LookupOption {
	if p, ok := r.(SearchListProvider); ok {
		return WithLookupSearchList(p.SearchList(), p.Ndots())
	}
	return lookupOption{option.New(identLookupSearchList{}, searchListSpec{})}
}

func applyLookupOptions(opts []LookupOption) searchListSpec {
	var spec searchListSpec
	for _, o := range opts {
		if o.Ident() == (identLookupSearchList{}) {
			spec = option.MustGet[searchListSpec](o)
		}
	}
	return spec
}

// MXRecord is the projection of an rdata.MX answer returned by LookupMX.
type MXRecord struct {
	Host       wire.Name
	Preference uint16
}

// SRVRecord is the projection of an rdata.SRV answer returned by LookupSRV.
type SRVRecord struct {
	Target   wire.Name
	Port     uint16
	Priority uint16
	Weight   uint16
}

// LookupHost dispatches A and AAAA queries for host concurrently and
// returns every address either query produced.
//
// By default LookupHost queries host as-given with NO search-list
// expansion. To enable expansion, pass [WithLookupSearchList] (explicit
// suffixes) or [SearchListDefaults](r) (use the resolver's configured
// list). Trailing-dot names bypass expansion regardless.
//
// SECURITY: search-list expansion sends queries for "host.<suffix>" to
// the configured upstream BEFORE the unsuffixed name on short inputs.
// Calls with untrusted host strings (e.g. "wpad") can disclose intent
// to the upstream and any on-path observer. The safe default — no
// expansion — addresses this; only opt in when you trust the host
// argument and accept the leak surface.
//
// A non-NoError RCODE on any individual sub-query is treated as a
// soft fail: LookupHost continues to the next candidate name. Only
// when no candidate produces addresses does the most recent error
// surface to the caller.
func LookupHost(ctx context.Context, r Resolver, host string, opts ...LookupOption) ([]netip.Addr, error) {
	spec := applyLookupOptions(opts)
	candidates, err := candidateNames(host, spec)
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

// LookupA queries the A records for name and returns their IPv4 addresses.
// name is expected to be an absolute DNS name; LookupA does NOT apply
// search-list expansion (use LookupHost for that). A non-NoError RCODE is
// surfaced as a typed *RCodeError.
func LookupA(ctx context.Context, r Resolver, name wire.Name) ([]netip.Addr, error) {
	rs, err := ResolveAs[rdata.A](ctx, r, name)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(rs))
	for _, v := range rs {
		out = append(out, v.Addr())
	}
	return out, nil
}

// LookupAAAA queries the AAAA records for name and returns their IPv6
// addresses. name is expected to be an absolute DNS name; LookupAAAA does NOT
// apply search-list expansion (use LookupHost for that).
func LookupAAAA(ctx context.Context, r Resolver, name wire.Name) ([]netip.Addr, error) {
	rs, err := ResolveAs[rdata.AAAA](ctx, r, name)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(rs))
	for _, v := range rs {
		out = append(out, v.Addr())
	}
	return out, nil
}

// LookupMX queries the MX records for name and returns them with the
// exchange host and preference fields surfaced. Records are returned in
// the order they appear in the answer; callers that need RFC 2782-style
// ranking should sort by Preference.
func LookupMX(ctx context.Context, r Resolver, name wire.Name) ([]MXRecord, error) {
	rs, err := ResolveAs[rdata.MX](ctx, r, name)
	if err != nil {
		return nil, err
	}
	out := make([]MXRecord, 0, len(rs))
	for _, v := range rs {
		out = append(out, MXRecord{Host: v.Exchange(), Preference: v.Preference()})
	}
	return out, nil
}

// LookupTXT queries the TXT records for name and returns each record's
// concatenated character strings as a single string. Most TXT-based
// protocols (SPF, DKIM, DMARC) expect concatenation of the per-record
// character strings; callers that need the raw string slices should use
// ResolveAs[rdata.TXT] directly.
func LookupTXT(ctx context.Context, r Resolver, name wire.Name) ([]string, error) {
	rs, err := ResolveAs[rdata.TXT](ctx, r, name)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rs))
	for _, v := range rs {
		out = append(out, strings.Join(v.Strings(), ""))
	}
	return out, nil
}

// LookupSRV queries the SRV records for name and returns them with target,
// port, priority and weight surfaced. Records are returned in answer order;
// callers that need RFC 2782 priority/weight ranking should sort externally.
func LookupSRV(ctx context.Context, r Resolver, name wire.Name) ([]SRVRecord, error) {
	rs, err := ResolveAs[rdata.SRV](ctx, r, name)
	if err != nil {
		return nil, err
	}
	out := make([]SRVRecord, 0, len(rs))
	for _, v := range rs {
		out = append(out, SRVRecord{
			Target:   v.Target(),
			Port:     v.Port(),
			Priority: v.Priority(),
			Weight:   v.Weight(),
		})
	}
	return out, nil
}

// LookupCNAME queries the CNAME records for name and returns the target
// names. Most callers will want LookupHost or LookupA/AAAA instead — the
// Resolver follows CNAME chains transparently — but applications that need
// the canonical name itself (e.g. DANE TLSA lookups) can use LookupCNAME.
func LookupCNAME(ctx context.Context, r Resolver, name wire.Name) ([]wire.Name, error) {
	rs, err := ResolveAs[rdata.CNAME](ctx, r, name)
	if err != nil {
		return nil, err
	}
	out := make([]wire.Name, 0, len(rs))
	for _, v := range rs {
		out = append(out, v.Target())
	}
	return out, nil
}

// LookupNS queries the NS records for name and returns the nameserver
// target names.
func LookupNS(ctx context.Context, r Resolver, name wire.Name) ([]wire.Name, error) {
	rs, err := ResolveAs[rdata.NS](ctx, r, name)
	if err != nil {
		return nil, err
	}
	out := make([]wire.Name, 0, len(rs))
	for _, v := range rs {
		out = append(out, v.Target())
	}
	return out, nil
}

// LookupPTR performs a reverse-DNS lookup for addr and returns the names
// the address resolves to. addr is converted to its RFC 1035 / RFC 3596
// reverse-form name (in-addr.arpa for IPv4, ip6.arpa for IPv6 nibble form)
// before querying.
func LookupPTR(ctx context.Context, r Resolver, addr netip.Addr) ([]wire.Name, error) {
	name, err := reverseAddr(addr)
	if err != nil {
		return nil, err
	}
	rs, err := ResolveAs[rdata.PTR](ctx, r, name)
	if err != nil {
		return nil, err
	}
	out := make([]wire.Name, 0, len(rs))
	for _, v := range rs {
		out = append(out, v.Target())
	}
	return out, nil
}

// reverseAddr builds the in-addr.arpa (IPv4) or ip6.arpa (IPv6) reverse-DNS
// name for addr. IPv4-mapped IPv6 addresses are unmapped to their IPv4
// form per the net package convention.
func reverseAddr(addr netip.Addr) (wire.Name, error) {
	if !addr.IsValid() {
		return wire.Name{}, fmt.Errorf("acidns: reverseAddr: invalid address")
	}
	addr = addr.Unmap()
	if addr.Is4() {
		b := addr.As4()
		s := fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", b[3], b[2], b[1], b[0])
		return wire.ParseName(s)
	}
	b := addr.As16()
	var sb strings.Builder
	const hex = "0123456789abcdef"
	for i := len(b) - 1; i >= 0; i-- {
		sb.WriteByte(hex[b[i]&0x0f])
		sb.WriteByte('.')
		sb.WriteByte(hex[b[i]>>4])
		sb.WriteByte('.')
	}
	sb.WriteString("ip6.arpa.")
	return wire.ParseName(sb.String())
}

// candidateNames builds the ordered list of FQDNs to attempt for a
// LookupHost call given the caller-supplied search-list spec. An
// empty spec or a trailing-dot host yields only the parsed host.
func candidateNames(host string, spec searchListSpec) ([]wire.Name, error) {
	absolute := strings.HasSuffix(host, ".")
	base, err := wire.ParseName(host)
	if err != nil {
		return nil, err
	}
	if absolute || len(spec.suffixes) == 0 {
		return []wire.Name{base}, nil
	}
	dots := strings.Count(strings.TrimSuffix(host, "."), ".")
	suffixed := make([]wire.Name, 0, len(spec.suffixes))
	for _, s := range spec.suffixes {
		n, err := wire.ParseName(host + "." + s.String())
		if err != nil {
			continue
		}
		suffixed = append(suffixed, n)
	}
	if dots >= spec.ndots {
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
