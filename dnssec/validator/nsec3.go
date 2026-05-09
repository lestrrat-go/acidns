package validator

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // RFC 5155 §5 fixes the hash algorithm at SHA-1.
	"errors"
	"fmt"
	"strings"

	"github.com/lestrrat-go/acidns/dnssec/validator/validatorbb"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// NSEC3HashSHA1 is the hash algorithm code for SHA-1 (RFC 5155 §11.2). It
// is the only NSEC3 hash algorithm registered with IANA; modern zones
// continue to use it because no successor has been standardised.
const NSEC3HashSHA1 = 1

// NSEC3FlagOptOut marks an NSEC3 record as opt-out (RFC 5155 §6). When set,
// unsigned delegations may exist between the record's owner-hash and its
// next-hashed-owner; a "covering" NSEC3 with this flag is therefore a
// proof of "no signed delegation" rather than "no name".
const NSEC3FlagOptOut uint8 = 0x01

// MaxNSEC3Iterations is the validator's hard cap on NSEC3 iterations,
// matching the conservative bound recommended by RFC 9276 §3.1. Records
// with a higher count are treated as Insecure (the resolver continues
// without DNSSEC validation for that response). Operationally most zones
// use 0; values above 100 have no defensive value and are pure CPU drag.
const MaxNSEC3Iterations uint16 = 100

// ErrNSEC3IterationsExceeded is returned when a record exceeds
// MaxNSEC3Iterations.
var ErrNSEC3IterationsExceeded = errors.New("validator: NSEC3 iterations exceed limit")

// nsec3Hash computes IH(salt, name, iterations) per RFC 5155 §5.1 — H(x ||
// salt) iterated `iterations` extra times after the initial round.
//
// The input name is rendered in canonical (lowercase) wire form. acidns
// stores names lowercase, so we use the existing AppendWire output.
func nsec3Hash(name wire.Name, salt []byte, iterations uint16) []byte {
	if iterations > MaxNSEC3Iterations {
		return nil
	}
	buf := name.AppendWire(nil)
	buf = append(buf, salt...)
	h := sha1.Sum(buf) //nolint:gosec
	for range iterations {
		next := make([]byte, 0, len(h)+len(salt))
		next = append(next, h[:]...)
		next = append(next, salt...)
		h = sha1.Sum(next) //nolint:gosec
	}
	return h[:]
}

// nsec3OwnerHash extracts the hash bytes from an NSEC3 owner. The leftmost
// label is base32hex; the remainder is the zone apex. Returns an error if
// the leftmost label fails to decode.
func nsec3OwnerHash(owner wire.Name) ([]byte, error) {
	for l := range owner.Labels() {
		// First label only.
		s := strings.ToUpper(string(l))
		return validatorbb.Base32HexDecode(s)
	}
	return nil, fmt.Errorf("validator: NSEC3 owner has no label")
}

// nsec3Match returns the NSEC3 record whose owner-hash matches H(name) under
// params. The bool indicates whether such a record was found.
func nsec3Match(name wire.Name, params nsec3Params, records []wire.Record) (rdata.NSEC3, bool) {
	want := nsec3Hash(name, params.salt, params.iterations)
	if want == nil {
		return rdata.NSEC3{}, false
	}
	for _, r := range records {
		if r.Type() != rrtype.NSEC3 {
			continue
		}
		got, err := nsec3OwnerHash(r.Name())
		if err != nil {
			continue
		}
		if bytes.Equal(got, want) {
			n3, ok := wire.RDataAs[rdata.NSEC3](r)
			if !ok {
				continue
			}
			return n3, true
		}
	}
	return rdata.NSEC3{}, false
}

// nsec3Cover returns the NSEC3 record whose (owner-hash, next-hash)
// interval covers H(name). RFC 5155 §6.2 — interval is (owner-hash,
// next-hash], with wraparound at the apex.
func nsec3Cover(name wire.Name, params nsec3Params, records []wire.Record) (rdata.NSEC3, bool) {
	target := nsec3Hash(name, params.salt, params.iterations)
	if target == nil {
		return rdata.NSEC3{}, false
	}
	for _, r := range records {
		if r.Type() != rrtype.NSEC3 {
			continue
		}
		ownerHash, err := nsec3OwnerHash(r.Name())
		if err != nil {
			continue
		}
		n3, ok := wire.RDataAs[rdata.NSEC3](r)
		if !ok {
			continue
		}
		next := n3.NextHashedOwner()
		if validatorbb.HashIntervalContains(ownerHash, next, target) {
			return n3, true
		}
	}
	return rdata.NSEC3{}, false
}

// nsec3Params bundles the (alg, iterations, salt) tuple shared by all NSEC3
// records in a zone (RFC 5155 §4.1.1; mismatched parameters are a protocol
// violation that validators MUST reject).
type nsec3Params struct {
	alg        uint8
	iterations uint16
	salt       []byte
}

// extractNSEC3Params returns the (alg, iterations, salt) from any NSEC3 in
// records. Returns ok=false if no NSEC3 records are present, if the
// records disagree (a protocol violation per RFC 5155 §4.1.1), or if
// the hash algorithm is anything other than SHA-1 — nsec3Hash always
// SHA-1s, so accepting any other algorithm would compute a proof
// against a hash the zone never published and weaken denial-of-existence.
func extractNSEC3Params(records []wire.Record) (nsec3Params, bool) {
	var params nsec3Params
	first := true
	for _, r := range records {
		if r.Type() != rrtype.NSEC3 {
			continue
		}
		n3, ok := wire.RDataAs[rdata.NSEC3](r)
		if !ok {
			continue
		}
		if n3.HashAlgorithm() != NSEC3HashSHA1 {
			// Reject the entire denial proof rather than per-record:
			// a single non-SHA-1 NSEC3 in the set means the proof is
			// uninterpretable to this validator.
			return nsec3Params{}, false
		}
		cur := nsec3Params{
			alg:        n3.HashAlgorithm(),
			iterations: n3.Iterations(),
			salt:       append([]byte(nil), n3.Salt()...),
		}
		if first {
			params = cur
			first = false
			continue
		}
		if cur.alg != params.alg || cur.iterations != params.iterations || !bytes.Equal(cur.salt, params.salt) {
			return nsec3Params{}, false
		}
	}
	return params, !first
}

// nsec3DenialKind classifies the outcome of an NSEC3 denial-of-existence
// check.
type nsec3DenialKind int

const (
	nsec3DenialNone nsec3DenialKind = iota
	nsec3DenialNoData
	nsec3DenialNXDomain
	nsec3DenialInsecureDelegation
	nsec3DenialOptOut
	// nsec3DenialIterationsExceeded indicates the records advertised a
	// hash-iteration count above MaxNSEC3Iterations. Per RFC 9276 §3.2 the
	// validator should treat such a response as Insecure (skip DNSSEC
	// validation) rather than Bogus, since the only honest interpretation
	// is that the zone configured a parameter we refuse to spend cycles
	// on, not that the proof is forged.
	nsec3DenialIterationsExceeded
)

// nsec3DenialResult bundles the proof outcome and supporting record
// references for diagnostics.
type nsec3DenialResult struct {
	kind            nsec3DenialKind
	closestEncloser wire.Name
}

// nsec3ProveDenial inspects an NSEC3 set in the authority section to
// classify a NoData / NXDOMAIN / insecure-delegation outcome for qname /
// qtype. Records must be the post-RRSIG-verification authority NSEC3
// records.
//
// RFC 5155 §8 split:
//
//   - §8.4 NoData: matching NSEC3 at qname with !qtype in bitmap.
//   - §8.5 NoData with wildcard: matching NSEC3 at *.<closest_encloser>.
//   - §8.6 NXDOMAIN: closest-encloser proof — match at encloser, cover at
//     next-closer, cover at *.encloser.
//   - §6   Opt-out: covering NSEC3 with opt-out flag set; outcomes that
//     would otherwise be Bogus become Insecure.
//   - DS-NoData (RFC 5155 §7.2.4): matching NSEC3 at delegation point
//     whose bitmap has NS but not DS — insecure delegation (or covering
//     opt-out NSEC3).
func nsec3ProveDenial(qname wire.Name, qtype rrtype.Type, zone wire.Name, records []wire.Record) nsec3DenialResult {
	params, ok := extractNSEC3Params(records)
	if !ok {
		return nsec3DenialResult{kind: nsec3DenialNone}
	}
	if params.iterations > MaxNSEC3Iterations {
		// Refuse to spend cycles on hostile zones; surface as Insecure
		// per RFC 9276 §3.2 so callers downgrade DNSSEC validation
		// rather than declaring Bogus on a parameter we won't engage.
		return nsec3DenialResult{kind: nsec3DenialIterationsExceeded}
	}

	// 1. DS-NoData / insecure-delegation handling (qtype == DS).
	if qtype == rrtype.DS {
		if n3, found := nsec3Match(qname, params, records); found {
			hasNS := bitmapHas(n3.Types(), rrtype.NS)
			hasDS := bitmapHas(n3.Types(), rrtype.DS)
			hasSOA := bitmapHas(n3.Types(), rrtype.SOA)
			switch {
			case hasNS && !hasDS && !hasSOA:
				return nsec3DenialResult{kind: nsec3DenialInsecureDelegation}
			case !hasDS:
				return nsec3DenialResult{kind: nsec3DenialNoData}
			}
		}
		// Opt-out covering: insecure delegation possible.
		if n3, found := nsec3Cover(qname, params, records); found {
			if n3.Flags()&NSEC3FlagOptOut != 0 {
				return nsec3DenialResult{kind: nsec3DenialOptOut}
			}
		}
	}

	// 2. NoData at qname (matching NSEC3 says qtype absent).
	if n3, found := nsec3Match(qname, params, records); found {
		if !bitmapHas(n3.Types(), qtype) {
			return nsec3DenialResult{kind: nsec3DenialNoData}
		}
	}

	// 3. NXDOMAIN closest-encloser proof.
	encloser, ok := findNSEC3ClosestEncloser(qname, zone, params, records)
	if !ok {
		return nsec3DenialResult{kind: nsec3DenialNone}
	}
	// Need NSEC3 covering "next closer name".
	nextCloser := validatorbb.NextCloserName(qname, encloser)
	if _, found := nsec3Cover(nextCloser, params, records); !found {
		return nsec3DenialResult{kind: nsec3DenialNone}
	}
	// Need NSEC3 covering *.<encloser> OR a matching wildcard NSEC3 with
	// !qtype in bitmap (§8.7).
	wildcard, err := validatorbb.WildcardOf(encloser)
	if err == nil {
		if _, found := nsec3Cover(wildcard, params, records); found {
			return nsec3DenialResult{kind: nsec3DenialNXDomain, closestEncloser: encloser}
		}
		if n3, found := nsec3Match(wildcard, params, records); found {
			if !bitmapHas(n3.Types(), qtype) {
				return nsec3DenialResult{kind: nsec3DenialNoData, closestEncloser: encloser}
			}
		}
	}
	return nsec3DenialResult{kind: nsec3DenialNone}
}

// findNSEC3ClosestEncloser walks ancestors of qname (starting at qname's
// parent and stopping at zone's apex) and returns the deepest ancestor
// whose hashed name is matched by an NSEC3 in records.
func findNSEC3ClosestEncloser(qname, zone wire.Name, params nsec3Params, records []wire.Record) (wire.Name, bool) {
	cur := qname
	for {
		parent, ok := cur.Parent()
		if !ok {
			return wire.Name{}, false
		}
		if _, found := nsec3Match(parent, params, records); found {
			return parent, true
		}
		if parent.Equal(zone) {
			// Zone apex always has an NSEC3; if not matched it's a
			// configuration error.
			if _, found := nsec3Match(zone, params, records); found {
				return zone, true
			}
			return wire.Name{}, false
		}
		cur = parent
	}
}
