package recursive

// Root server priming (RFC 8109). At startup the resolver knows a
// hard-coded snapshot of the root server list. That list drifts over
// time as IANA reorganises operators. Priming replaces the in-memory
// list at runtime: query NS . against the configured roots, and
// trust the authoritative reply for the new list.
//
// The priming query itself does not need DNSSEC validation — we only
// care about discovering the operator names; the addresses we use to
// reach them come from glue + a follow-up A/AAAA resolve, which is
// where ordinary recursion's bailiwick + (optionally) DNSSEC
// protections apply.

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// defaultRootRefreshInterval is the cadence at which Run refreshes
// the root list when [WithRootPriming] is enabled without an
// explicit interval. RFC 8109 §3 recommends "no more often than
// once per hour"; 24 hours is well within that and matches what
// production resolvers (Unbound, BIND) do by default.
const defaultRootRefreshInterval = 24 * time.Hour

// currentRoots returns a snapshot of the live root server list under
// the rootsMu read lock. When the in-memory list is empty — neither
// [WithRoots] supplied a list nor a successful prime has populated
// one — the IANA snapshot in [iANARootHints] is returned so an
// operator who calls [New] with no options still gets working
// recursion out of the box.
func (r *Recursive) currentRoots() []netip.AddrPort {
	r.rootsMu.RLock()
	defer r.rootsMu.RUnlock()
	if len(r.roots) == 0 {
		return append([]netip.AddrPort(nil), iANARootHints...)
	}
	return append([]netip.AddrPort(nil), r.roots...)
}

// setRoots atomically replaces the root server list. A nil/empty
// list is rejected — we never want to leave the resolver with no
// roots to bootstrap from.
func (r *Recursive) setRoots(addrs []netip.AddrPort) error {
	if len(addrs) == 0 {
		return errors.New("recursive: refusing to set empty root list")
	}
	r.rootsMu.Lock()
	r.roots = append(r.roots[:0], addrs...)
	r.rootsMu.Unlock()
	return nil
}

// Prime performs one priming exchange. Failure leaves the existing
// root list untouched.
func (r *Recursive) Prime(ctx context.Context) error {
	servers := r.currentRoots()
	if len(servers) == 0 {
		return errors.New("recursive: no configured roots to prime from")
	}
	resp, _, err := r.queryAny(ctx, servers, wire.RootName(), rrtype.NS)
	if err != nil {
		return err
	}
	if resp.Flags().RCODE() != wire.RCODENoError {
		return errors.New("recursive: priming response was not NoError")
	}
	addrs := primingAddrsFromResponse(resp)
	if len(addrs) == 0 {
		return errors.New("recursive: priming response had no usable glue")
	}
	return r.setRoots(addrs)
}

// primingAddrsFromResponse extracts root server addresses from a
// priming response. Trusts only glue records whose owner matches an
// NS target in the answer/authority — anything else would let a
// hostile root serve poisoned addresses for unrelated names.
func primingAddrsFromResponse(resp wire.Message) []netip.AddrPort {
	wantedNS := make(map[string]struct{})
	for _, sec := range [][]wire.Record{resp.Answers(), resp.Authorities()} {
		for _, rec := range sec {
			if rec.Type() != rrtype.NS || !rec.Name().Equal(wire.RootName()) {
				continue
			}
			ns, ok := wire.RDataAs[rdata.NS](rec)
			if !ok {
				continue
			}
			wantedNS[nameKey(ns.NSDName())] = struct{}{}
		}
	}
	if len(wantedNS) == 0 {
		return nil
	}
	var out []netip.AddrPort
	for _, rec := range resp.Additionals() {
		if _, ok := wantedNS[nameKey(rec.Name())]; !ok {
			continue
		}
		switch v := rec.RData().(type) {
		case rdata.A:
			out = append(out, netip.AddrPortFrom(v.Addr(), 53))
		case rdata.AAAA:
			out = append(out, netip.AddrPortFrom(v.Addr(), 53))
		}
	}
	return out
}

// RunMaintenance drives background maintenance: root priming (RFC
// 8109) when configured, and periodic sweep of expired
// aggressive-NSEC entries when WithAggressiveNSEC is on. Returns
// nil immediately when no background tasks are configured so the
// call is always safe.
//
// This method BLOCKS until ctx is canceled. The name disambiguates
// from the non-blocking server-side Run (e.g. UDPServer.Run).
func (r *Recursive) RunMaintenance(ctx context.Context) error {
	if !r.rootPriming && !r.aggressiveNSEC {
		return nil
	}

	if r.rootPriming {
		// Initial prime — best-effort. If it fails the configured roots
		// remain in place, which is the same situation as a resolver
		// that never primes at all.
		_ = r.Prime(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}

	// Aggressive NSEC sweep cadence: 1/8 of the root refresh when
	// priming is on, otherwise a stand-alone 5-minute tick.
	const aggressiveSweepDefault = 5 * time.Minute
	sweepInterval := aggressiveSweepDefault
	if r.rootPriming && r.rootRefresh/8 > time.Second {
		sweepInterval = r.rootRefresh / 8
	}

	var primeC <-chan time.Time
	if r.rootPriming {
		t := time.NewTicker(r.rootRefresh)
		defer t.Stop()
		primeC = t.C
	}
	var sweepC <-chan time.Time
	if r.aggressiveNSEC {
		t := time.NewTicker(sweepInterval)
		defer t.Stop()
		sweepC = t.C
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-primeC:
			_ = r.Prime(ctx)
		case <-sweepC:
			now := time.Now()
			if r.nsecIdx != nil {
				r.nsecIdx.SweepExpired(now)
			}
			if r.nsec3Idx != nil {
				r.nsec3Idx.SweepExpired(now)
			}
		}
	}
}
