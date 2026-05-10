package validator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/acidns/dnssec"
	"github.com/lestrrat-go/acidns/dnssec/validator/validatorbb"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/option/v3"
)

// ErrNoTrustAnchor is returned when no configured Anchor covers the query
// name. The Walker classifies the answer Indeterminate.
var ErrNoTrustAnchor = errors.New("validator: no trust anchor covers query")

// ErrIterationLimit is returned when the walker hits a configured iteration
// cap (zone-cut count, RRSIGs tried per RRset, or algorithms per zone).
// Production callers should treat this as Bogus and surface EDE 4
// (Signature Expired) or EDE 6 (DNSSEC Bogus).
var ErrIterationLimit = errors.New("validator: iteration limit exceeded")

// ErrAlgorithmIncomplete is returned when a parent's DS RRset advertises an
// algorithm for which the child has no signing DNSKEY+RRSIG (RFC 6840 §5.11).
var ErrAlgorithmIncomplete = errors.New("validator: algorithm coverage incomplete")

// ErrUnsignedAnswer is returned when the answer at qname has no covering
// RRSIG and the chain shows the answer's zone IS signed (i.e. an attacker
// stripped the signatures, or the response is malformed).
var ErrUnsignedAnswer = errors.New("validator: answer is unsigned in a signed zone")

// errNXDomainAtCandidate is an internal sentinel indicating the chain walk
// terminated because the parent zone proved qname does not exist.
var errNXDomainAtCandidate = errors.New("validator: nxdomain at candidate")

// errInsecureNSEC3Iterations is an internal sentinel indicating the
// authority section's NSEC3 records advertise an iteration count the
// validator refuses to process. Per RFC 9276 §3.2 callers map this to
// an Insecure (not Bogus) answer.
var errInsecureNSEC3Iterations = errors.New("validator: NSEC3 iterations exceed limit (RFC 9276 §3.2)")

// Walker walks the DNSSEC chain of trust from a configured Anchor down to
// a queried (name, type), validating every link. Implementations are safe
// for concurrent use by multiple goroutines; the underlying Source is
// expected to be safe likewise.
type Walker interface {
	Resolve(ctx context.Context, qname wire.Name, qtype rrtype.Type) (Answer, error)
}

// Answer captures the outcome of a chain-walked validation.
type Answer interface {
	// Result classifies the answer per RFC 4035 §4.3.
	Result() Result
	// Records returns the validated answer RRset for Result==Secure;
	// for Insecure it returns the unvalidated answer the upstream gave;
	// for Bogus and Indeterminate it returns whatever was supplied
	// (possibly empty) so callers can log diagnostics.
	Records() []wire.Record
	// RCODE is the RCODE carried by the upstream's terminal answer.
	RCODE() wire.RCODE
	// Chain returns the audit trail: one ChainStep per zone cut traversed,
	// from the trust anchor to the answer's zone (inclusive).
	Chain() []ChainStep
	// Reason is the underlying error for Result!=Secure (nil otherwise).
	Reason() error
}

// ChainStep records a single zone in the validated chain.
type ChainStep interface {
	Zone() wire.Name
	DNSKEYs() []rdata.DNSKEY
	DSs() []rdata.DS
	Result() Result
}

type chainStep struct {
	zone wire.Name
	keys []rdata.DNSKEY
	dss  []rdata.DS
	res  Result
}

func (s chainStep) Zone() wire.Name         { return s.zone }
func (s chainStep) DNSKEYs() []rdata.DNSKEY { return s.keys }
func (s chainStep) DSs() []rdata.DS         { return s.dss }
func (s chainStep) Result() Result          { return s.res }

type answer struct {
	result  Result
	records []wire.Record
	rcode   wire.RCODE
	chain   []ChainStep
	reason  error
}

func (a *answer) Result() Result         { return a.result }
func (a *answer) Records() []wire.Record { return a.records }
func (a *answer) RCODE() wire.RCODE      { return a.rcode }
func (a *answer) Chain() []ChainStep     { return a.chain }
func (a *answer) Reason() error          { return a.reason }

type walker struct {
	source       Source
	anchors      []Anchor
	ntas         *NTAStore
	now          func() time.Time
	skew         time.Duration
	bogusPolicy  BogusPolicy
	maxZoneCuts  int
	maxRRSIGsTry int
	maxAlgs      int
	// maxKeys caps the number of usable DNSKEYs (post-protocol /
	// post-revoke filter) the walker will accept from any one zone.
	// Without this, a zone publishing many DNSKEYs that share a
	// keytag drives `maxRRSIGsTry × N` candidate Verify calls per
	// signed RRset (cf. CVE-2023-50387 KeyTrap). Default 16; raise
	// only with concrete evidence of a legitimate larger keyset.
	maxKeys int
}

// NewWalker constructs a Walker. A Source is required, and at least one
// trust anchor must be configured via [WithWalkerAnchors] or
// [WithWalkerIANARootAnchor]. An unconfigured walker returns
// [ErrNoTrustAnchor] from Resolve so callers cannot accidentally rely
// on an embedded root anchor that ages with each ICANN KSK rollover.
func NewWalker(source Source, opts ...WalkerOption) (Walker, error) {
	if source == nil {
		return nil, fmt.Errorf("validator: NewWalker requires a non-nil Source")
	}
	w := &walker{
		source:       source,
		ntas:         NewNTAStore(),
		now:          time.Now,
		skew:         0,
		bogusPolicy:  BogusReturnSERVFAIL,
		maxZoneCuts:  16,
		maxRRSIGsTry: 8,
		maxAlgs:      4,
		maxKeys:      16,
	}
	for _, o := range opts {
		switch o.Ident() {
		case identWalkerAnchors{}:
			anchors := option.MustGet[[]Anchor](o)
			w.anchors = append(w.anchors[:0], anchors...)
		case identWalkerIANARootAnchor{}:
			if option.MustGet[bool](o) {
				w.anchors = append(w.anchors, IANARootAnchor())
			}
		case identWalkerNTAStore{}:
			if s := option.MustGet[*NTAStore](o); s != nil {
				w.ntas = s
			}
		case identWalkerBogusPolicy{}:
			w.bogusPolicy = option.MustGet[BogusPolicy](o)
		case identWalkerClock{}:
			if now := option.MustGet[func() time.Time](o); now != nil {
				w.now = now
			}
		case identWalkerClockSkew{}:
			if skew := option.MustGet[time.Duration](o); skew >= 0 {
				w.skew = skew
			}
		case identWalkerMaxZoneCuts{}:
			if n := option.MustGet[int](o); n > 0 {
				w.maxZoneCuts = n
			}
		case identWalkerMaxRRSIGsTry{}:
			if n := option.MustGet[int](o); n > 0 {
				w.maxRRSIGsTry = n
			}
		case identWalkerMaxAlgorithms{}:
			if n := option.MustGet[int](o); n > 0 {
				w.maxAlgs = n
			}
		case identWalkerMaxKeysPerZone{}:
			if n := option.MustGet[int](o); n > 0 {
				w.maxKeys = n
			}
		}
	}
	return w, nil
}

// Resolve performs the chain walk and returns the validated Answer.
//
// The returned error mirrors Answer.Reason() for non-Secure outcomes when
// BogusPolicy is BogusReturnSERVFAIL; under BogusReturnAnswer the error is
// always nil for Bogus (the caller inspects Result/Reason on the Answer).
func (w *walker) Resolve(ctx context.Context, qname wire.Name, qtype rrtype.Type) (Answer, error) {
	if !qname.IsValid() {
		return nil, fmt.Errorf("validator: invalid qname")
	}

	if w.ntas.Covers(qname) {
		return w.indeterminate(qname, qtype, nil, "NTA covers qname"), nil
	}

	anchor, ok := closestAnchor(w.anchors, qname)
	if !ok {
		return w.indeterminate(qname, qtype, ErrNoTrustAnchor, ""), ErrNoTrustAnchor
	}

	chain, parentKeys, insecureFrom, err := w.walkChain(ctx, anchor, qname)
	if err != nil {
		if errors.Is(err, errNXDomainAtCandidate) {
			// Walker validated NXDOMAIN at qname's parent zone.
			return &answer{
				result:  Secure,
				records: nil,
				rcode:   wire.RCODENXDomain,
				chain:   chain,
			}, nil
		}
		return w.bogus(qname, qtype, chain, err)
	}

	// Insecure delegation observed; query the answer but expect no signatures.
	if insecureFrom.IsValid() {
		msg, err := w.source.Lookup(ctx, qname, qtype)
		if err != nil {
			return w.bogus(qname, qtype, chain, fmt.Errorf("validator: lookup: %w", err))
		}
		ans := &answer{
			result:  Insecure,
			records: msg.Answers(),
			rcode:   msg.Flags().RCODE(),
			chain:   chain,
		}
		return ans, nil
	}

	// We are at the (presumed) signing zone for qname. Fetch the answer.
	msg, err := w.source.Lookup(ctx, qname, qtype)
	if err != nil {
		return w.bogus(qname, qtype, chain, fmt.Errorf("validator: answer lookup: %w", err))
	}

	rcode := msg.Flags().RCODE()
	answers := msg.Answers()

	// Positive answer: validate RRSIGs over each RRset of qtype at qname.
	if rcode == wire.RCODENoError && len(answers) > 0 {
		matching := validatorbb.RecordsOfType(answers, qtype, qname)
		if len(matching) == 0 {
			// Could be a CNAME chain — caller's responsibility (resolver
			// follows CNAMEs). For the walker we treat as no-data.
			return w.validateNoData(qname, qtype, parentKeys, msg, chain)
		}
		sigs := rrsigsForTypeAndOwner(extractRRSIGs(answers), qtype, qname)
		if len(sigs) == 0 {
			return w.bogus(qname, qtype, chain, ErrUnsignedAnswer)
		}
		requiredAlgs := signingAlgorithms(chain)
		err := w.verifyRRsetAllAlgs(matching, sigs, parentKeys, requiredAlgs)
		if err != nil {
			return w.bogus(qname, qtype, chain, fmt.Errorf("validator: answer rrsig: %w", err))
		}
		// RFC 4035 §5.3.4: when the answer was synthesised from a
		// wildcard (RRSIG.Labels < owner.NumLabels), the responder MUST
		// also supply an NSEC/NSEC3 proof that qname does not exist
		// directly in the zone. Without this check, an attacker holding
		// a single valid wildcard signature can fabricate Secure
		// answers for any non-existent name in that subtree —
		// re-signing isn't required because the wildcard's RRSIG itself
		// authenticates the synthesised owner.
		if encloserLabels, wildcard := wildcardSynthLabels(qname, sigs); wildcard {
			if err := w.validateWildcardNextCloser(qname, encloserLabels, parentKeys, msg); err != nil {
				return w.bogus(qname, qtype, chain, fmt.Errorf("validator: wildcard next-closer: %w", err))
			}
		}
		return &answer{
			result:  Secure,
			records: matching,
			rcode:   rcode,
			chain:   chain,
		}, nil
	}

	// NXDOMAIN or no-data: validate denial of existence with NSEC.
	return w.validateNegative(qname, qtype, parentKeys, msg, chain)
}

// walkChain builds the validated DNSKEY chain from anchor down to the
// signing zone of qname.
//
// Returns:
//
//   - chain: ordered ChainSteps from anchor → answer zone (inclusive).
//   - parentKeys: the DNSKEYs that sign records at the deepest secured zone
//     (i.e. the zone the answer is expected to be signed under).
//   - insecureFrom: an empty Name if the chain is fully secure; otherwise the
//     zone at which an insecure delegation was proven, meaning the caller
//     should not expect signatures on the answer.
//   - err: chain-walking failure (Bogus territory).
func (w *walker) walkChain(ctx context.Context, anchor Anchor, qname wire.Name) ([]ChainStep, []rdata.DNSKEY, wire.Name, error) {
	// Bootstrap at anchor: fetch DNSKEY, validate against anchor.DSs().
	keys, err := w.fetchAndVerifyDNSKEY(ctx, anchor.Name(), anchor.DSs())
	if err != nil {
		return nil, nil, wire.Name{}, fmt.Errorf("anchor %s: %w", anchor.Name(), err)
	}
	chain := []ChainStep{chainStep{zone: anchor.Name(), keys: keys, dss: anchor.DSs(), res: Secure}}

	parentKeys := keys
	zone := anchor.Name()

	// Walk one label at a time toward qname. Each candidate is qname
	// truncated to (zone.NumLabels()+1) labels.
	for {
		if zone.Equal(qname) {
			return chain, parentKeys, wire.Name{}, nil
		}
		if len(chain) > w.maxZoneCuts {
			return chain, nil, wire.Name{}, ErrIterationLimit
		}
		nextLabels := zone.NumLabels() + 1
		if nextLabels > qname.NumLabels() {
			return chain, parentKeys, wire.Name{}, nil
		}
		candidate := validatorbb.TruncateNameTo(qname, nextLabels)

		// NTA short-circuit: if NTA covers candidate or any descendant
		// reaching qname, stop validating from here.
		if w.ntas.Covers(candidate) {
			return chain, parentKeys, candidate, nil
		}

		dsMsg, err := w.source.Lookup(ctx, candidate, rrtype.DS)
		if err != nil {
			return chain, nil, wire.Name{}, fmt.Errorf("DS lookup %s: %w", candidate, err)
		}
		switch outcome, dsRRs, errDS := w.classifyDSResponse(candidate, zone, parentKeys, dsMsg); outcome {
		case dsOutcomeCut:
			// Real zone cut. Verify the DS rrset is signed by parentKeys
			// (already done in classifyDSResponse). Now pull DNSKEYs at
			// candidate and verify against the new DS list.
			childKeys, err := w.fetchAndVerifyDNSKEY(ctx, candidate, dsRRs)
			if err != nil {
				return chain, nil, wire.Name{}, fmt.Errorf("DNSKEY %s: %w", candidate, err)
			}
			chain = append(chain, chainStep{zone: candidate, keys: childKeys, dss: dsRRs, res: Secure})
			zone = candidate
			parentKeys = childKeys
		case dsOutcomeInsecure:
			// Proven insecure delegation: NS present at candidate, DS absent.
			// The subtree from candidate is unsigned.
			chain = append(chain, chainStep{zone: candidate, res: Insecure})
			return chain, parentKeys, candidate, nil
		case dsOutcomeNonCut:
			// candidate is a non-cut node under zone — keep walking.
			// (This is unusual; most names along a query path are zone
			// cuts. We handle it conservatively.)
			zone = candidate
		case dsOutcomeNXDomain:
			// The parent zone proved candidate doesn't exist. If candidate
			// is qname, that's a validated NXDOMAIN — surface it through
			// the answer path. Otherwise the chain is broken.
			if candidate.Equal(qname) {
				chain = append(chain, chainStep{zone: candidate, res: Secure})
				return chain, parentKeys, candidate, errNXDomainAtCandidate
			}
			return chain, nil, wire.Name{}, fmt.Errorf("validator: name %s does not exist (NXDOMAIN at chain step)", candidate)
		default:
			return chain, nil, wire.Name{}, fmt.Errorf("DS classify %s: %w", candidate, errDS)
		}
	}
}

// fetchAndVerifyDNSKEY queries the DNSKEY rrset at zone and returns the
// trusted DNSKEYs after verifying the rrset against the supplied DS list
// (KSK match) and confirming RFC 6840 §5.11 algorithm completeness.
func (w *walker) fetchAndVerifyDNSKEY(ctx context.Context, zone wire.Name, dss []rdata.DS) ([]rdata.DNSKEY, error) {
	msg, err := w.source.Lookup(ctx, zone, rrtype.DNSKEY)
	if err != nil {
		return nil, fmt.Errorf("DNSKEY lookup: %w", err)
	}
	dnskeyRRs := validatorbb.RecordsOfType(msg.Answers(), rrtype.DNSKEY, zone)
	if len(dnskeyRRs) == 0 {
		return nil, fmt.Errorf("validator: no DNSKEY rrset at %s", zone)
	}
	// KeyTrap pre-filter cap. The post-filter cap below catches a zone
	// that publishes too many usable keys, but counts only after the
	// protocol/revoke/Zone-bit filter. A hostile zone publishing tens
	// of thousands of garbage DNSKEYs would still allocate the parsed
	// slice and walk every record once at the filter step before they
	// get dropped. Cap the input slice at maxKeys * 4 (slack for
	// revoked/non-Zone keys present during a legitimate rollover) so
	// the per-record cost is bounded by the cap.
	preCap := w.maxKeys * 4
	if preCap > 0 && len(dnskeyRRs) > preCap {
		return nil, fmt.Errorf("%w: zone %s advertises %d DNSKEY records pre-filter (cap %d, KeyTrap guard)",
			ErrIterationLimit, zone, len(dnskeyRRs), preCap)
	}
	keys := make([]rdata.DNSKEY, 0, len(dnskeyRRs))
	for _, r := range dnskeyRRs {
		k, ok := wire.RDataAs[rdata.DNSKEY](r)
		if !ok {
			return nil, fmt.Errorf("validator: bad DNSKEY rdata at %s", zone)
		}
		// RFC 4034 §2.1.1 (Zone-Key flag), §2.1.2 (Protocol == 3) and
		// RFC 5011 §2.1 (Revoke flag) gate which DNSKEYs may
		// authenticate RRsets. Skip rather than error so a zone
		// publishing a single revoked or non-Zone key alongside live
		// ones still validates against the live keys; rejecting all
		// would deny service during a legitimate rollover.
		if k.Protocol() != 3 || k.Flags()&rdata.DNSKEYFlagRevoke != 0 {
			continue
		}
		if k.Flags()&rdata.DNSKEYFlagZone == 0 {
			continue
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("validator: no usable DNSKEY at %s (all revoked or wrong protocol)", zone)
	}
	if len(keys) > w.maxKeys {
		return nil, fmt.Errorf("%w: zone %s advertises %d DNSKEYs (cap %d, KeyTrap guard)",
			ErrIterationLimit, zone, len(keys), w.maxKeys)
	}

	// Find at least one KSK that matches a DS. Track which DSs were
	// satisfied so we can ensure every parent DS algorithm was covered.
	satisfiedAlgs := map[rdata.DNSSECAlgorithm]struct{}{}
	parentAlgs := map[rdata.DNSSECAlgorithm]struct{}{}
	for _, ds := range dss {
		parentAlgs[ds.Algorithm()] = struct{}{}
	}
	if len(parentAlgs) > w.maxAlgs {
		return nil, ErrIterationLimit
	}

	var trustedKSKs []rdata.DNSKEY
	for _, ds := range dss {
		for _, key := range keys {
			if dnssec.KeyTag(key) != ds.KeyTag() || key.Algorithm() != ds.Algorithm() {
				continue
			}
			if err := dnssec.VerifyDS(zone, ds, key); err != nil {
				continue
			}
			trustedKSKs = append(trustedKSKs, key)
			satisfiedAlgs[ds.Algorithm()] = struct{}{}
			break
		}
	}
	if len(trustedKSKs) == 0 {
		return nil, fmt.Errorf("validator: no DNSKEY at %s matched any DS", zone)
	}

	// The DNSKEY rrset MUST be self-signed by one of the trusted KSKs.
	sigs := rrsigsForTypeAndOwner(extractRRSIGs(msg.Answers()), rrtype.DNSKEY, zone)
	if len(sigs) == 0 {
		return nil, fmt.Errorf("validator: no RRSIG over DNSKEY at %s", zone)
	}
	if err := w.verifyRRsetWithKeys(dnskeyRRs, sigs, trustedKSKs); err != nil {
		return nil, fmt.Errorf("DNSKEY rrset rrsig: %w", err)
	}

	// RFC 6840 §5.11: every algorithm in the parent's DS list must have a
	// signing pair that actually verifies the DNSKEY rrset. The earlier
	// keytag-only match was insufficient — a forged RRSIG with the right
	// keytag but invalid signature would falsely satisfy completeness.
	now := w.now()
	signingAlgs := map[rdata.DNSSECAlgorithm]struct{}{}
	tries := 0
	for _, sig := range sigs {
		if _, need := parentAlgs[sig.Algorithm()]; !need {
			continue
		}
		if _, done := signingAlgs[sig.Algorithm()]; done {
			continue
		}
		if !validatorbb.RRSIGValidNowWithSkew(sig, now, w.skew) {
			continue
		}
		for _, key := range keys {
			if dnssec.KeyTag(key) != sig.KeyTag() || key.Algorithm() != sig.Algorithm() {
				continue
			}
			tries++
			if tries > w.maxRRSIGsTry {
				break
			}
			if err := dnssec.Verify(dnskeyRRs, sig, key); err == nil {
				signingAlgs[sig.Algorithm()] = struct{}{}
				break
			}
		}
		if tries > w.maxRRSIGsTry {
			break
		}
	}
	for alg := range parentAlgs {
		if _, ok := signingAlgs[alg]; !ok {
			return nil, fmt.Errorf("%w: alg %d not signed at %s", ErrAlgorithmIncomplete, alg, zone)
		}
	}
	return keys, nil
}

// dsOutcome enumerates the four possible classifications of a DS query.
type dsOutcome int

const (
	dsOutcomeUnknown  dsOutcome = iota
	dsOutcomeCut                // DS RRset present and signature-verified
	dsOutcomeInsecure           // signed proof of NoData(DS) where NSEC bitmap has NS
	dsOutcomeNonCut             // signed proof of NoData(DS) where NS bit absent
	dsOutcomeNXDomain           // signed proof that candidate doesn't exist
)

// classifyDSResponse interprets a DS-query response. parentKeys are the
// DNSKEYs of the parent zone (parentZone) authoritative for candidate's DS.
func (w *walker) classifyDSResponse(candidate, parentZone wire.Name, parentKeys []rdata.DNSKEY, msg wire.Message) (dsOutcome, []rdata.DS, error) {
	rcode := msg.Flags().RCODE()
	if rcode == wire.RCODENXDomain {
		if err := w.validateNXDomain(candidate, parentZone, parentKeys, msg); err != nil {
			return dsOutcomeUnknown, nil, fmt.Errorf("NXDOMAIN proof: %w", err)
		}
		return dsOutcomeNXDomain, nil, nil
	}

	// Look for a DS RRset in the answer section.
	dsRRs := validatorbb.RecordsOfType(msg.Answers(), rrtype.DS, candidate)
	if len(dsRRs) > 0 {
		dsRDatas := make([]rdata.DS, 0, len(dsRRs))
		for _, r := range dsRRs {
			d, ok := wire.RDataAs[rdata.DS](r)
			if !ok {
				return dsOutcomeUnknown, nil, fmt.Errorf("validator: bad DS rdata at %s", candidate)
			}
			dsRDatas = append(dsRDatas, d)
		}
		sigs := rrsigsForTypeAndOwner(extractRRSIGs(msg.Answers()), rrtype.DS, candidate)
		if len(sigs) == 0 {
			return dsOutcomeUnknown, nil, fmt.Errorf("validator: no RRSIG over DS at %s", candidate)
		}
		if err := w.verifyRRsetWithKeys(dsRRs, sigs, parentKeys); err != nil {
			return dsOutcomeUnknown, nil, fmt.Errorf("DS rrsig: %w", err)
		}
		return dsOutcomeCut, dsRDatas, nil
	}

	// No DS in answer: try NSEC first, then NSEC3.
	if outcome, ok, err := w.classifyDSViaNSEC(candidate, parentKeys, msg); ok {
		return outcome, nil, err
	}
	if outcome, ok, err := w.classifyDSViaNSEC3(candidate, parentZone, parentKeys, msg); ok {
		return outcome, nil, err
	}
	return dsOutcomeUnknown, nil, fmt.Errorf("validator: NoData(DS) at %s missing NSEC/NSEC3 proof", candidate)
}

// classifyDSViaNSEC handles the NSEC denial path. Returns ok=false if no
// NSEC records are present so the caller can try NSEC3.
func (w *walker) classifyDSViaNSEC(candidate wire.Name, parentKeys []rdata.DNSKEY, msg wire.Message) (dsOutcome, bool, error) {
	nsecRRs := validatorbb.RecordsOfType(msg.Authorities(), rrtype.NSEC, candidate)
	if len(nsecRRs) == 0 {
		nsecRRs = validatorbb.FilterNSECByOwner(msg.Authorities(), candidate)
	}
	if len(nsecRRs) == 0 {
		return dsOutcomeUnknown, false, nil
	}
	sigs := rrsigsForTypeAndOwner(extractRRSIGs(msg.Authorities()), rrtype.NSEC, candidate)
	if len(sigs) == 0 {
		return dsOutcomeUnknown, true, fmt.Errorf("validator: NSEC at %s lacks RRSIG", candidate)
	}
	if err := w.verifyRRsetWithKeys(nsecRRs, sigs, parentKeys); err != nil {
		return dsOutcomeUnknown, true, fmt.Errorf("NSEC rrsig: %w", err)
	}
	for _, r := range nsecRRs {
		nsec, ok := wire.RDataAs[rdata.NSEC](r)
		if !ok {
			continue
		}
		hasNS := bitmapHas(nsec.Types(), rrtype.NS)
		hasDS := bitmapHas(nsec.Types(), rrtype.DS)
		hasSOA := bitmapHas(nsec.Types(), rrtype.SOA)
		switch {
		case hasNS && !hasDS && !hasSOA:
			return dsOutcomeInsecure, true, nil
		case !hasDS:
			return dsOutcomeNonCut, true, nil
		}
	}
	return dsOutcomeUnknown, true, fmt.Errorf("validator: NSEC at %s did not prove DS absence", candidate)
}

// classifyDSViaNSEC3 handles the NSEC3 denial path. Returns ok=false if no
// NSEC3 records are present.
func (w *walker) classifyDSViaNSEC3(candidate, parentZone wire.Name, parentKeys []rdata.DNSKEY, msg wire.Message) (dsOutcome, bool, error) {
	nsec3RRs := recordsOfType3(msg.Authorities())
	if len(nsec3RRs) == 0 {
		return dsOutcomeUnknown, false, nil
	}
	if err := w.verifyNSEC3Set(nsec3RRs, msg.Authorities(), parentKeys); err != nil {
		return dsOutcomeUnknown, true, fmt.Errorf("NSEC3 rrsig: %w", err)
	}
	res := nsec3ProveDenial(candidate, rrtype.DS, parentZone, nsec3RRs)
	switch res.kind {
	case nsec3DenialInsecureDelegation, nsec3DenialOptOut:
		return dsOutcomeInsecure, true, nil
	case nsec3DenialIterationsExceeded:
		// RFC 9276 §3.2: high iteration counts downgrade to Insecure.
		return dsOutcomeInsecure, true, nil
	case nsec3DenialNoData:
		return dsOutcomeNonCut, true, nil
	}
	return dsOutcomeUnknown, true, fmt.Errorf("validator: NSEC3 at %s did not prove DS absence", candidate)
}

// validateNXDomain validates an NXDOMAIN response using NSEC OR NSEC3.
// When the authority section carries NSEC records, the NSEC proof's
// success or failure is authoritative — falling through to NSEC3 on
// NSEC failure would mask a forged-but-incomplete NSEC NXDOMAIN proof
// (RFC 4035 §5.4) behind a generic "no NSEC3 in authority" error.
func (w *walker) validateNXDomain(qname, parentZone wire.Name, parentKeys []rdata.DNSKEY, msg wire.Message) error {
	hasNSEC := len(allNSEC(msg.Authorities())) > 0
	hasNSEC3 := len(recordsOfType3(msg.Authorities())) > 0
	if hasNSEC {
		return w.validateNSECNXDomain(qname, parentKeys, msg)
	}
	if hasNSEC3 {
		return w.validateNSEC3NXDomain(qname, parentZone, parentKeys, msg)
	}
	return fmt.Errorf("validator: NXDOMAIN proof: no NSEC or NSEC3 in authority")
}

// validateNSEC3NXDomain validates an NXDOMAIN response using NSEC3
// closest-encloser proof. parentZone is the zone whose keys signed the
// authority section.
func (w *walker) validateNSEC3NXDomain(qname, parentZone wire.Name, parentKeys []rdata.DNSKEY, msg wire.Message) error {
	nsec3RRs := recordsOfType3(msg.Authorities())
	if len(nsec3RRs) == 0 {
		return fmt.Errorf("no NSEC3 in authority")
	}
	if err := w.verifyNSEC3Set(nsec3RRs, msg.Authorities(), parentKeys); err != nil {
		return fmt.Errorf("NSEC3 rrsig: %w", err)
	}
	res := nsec3ProveDenial(qname, 0, parentZone, nsec3RRs)
	switch res.kind {
	case nsec3DenialNXDomain:
		return nil
	case nsec3DenialOptOut:
		return nil
	case nsec3DenialIterationsExceeded:
		return errInsecureNSEC3Iterations
	}
	return fmt.Errorf("NSEC3 did not prove NXDOMAIN for %s", qname)
}

// verifyNSEC3Set verifies each NSEC3 rrset (grouped by owner) in records
// against parentKeys. authority is the full authority section the rrsets
// were drawn from (used to find covering RRSIGs).
func (w *walker) verifyNSEC3Set(nsec3RRs, authority []wire.Record, parentKeys []rdata.DNSKEY) error {
	groups := validatorbb.GroupRecordsByOwner(nsec3RRs)
	allSigs := extractRRSIGs(authority)
	for _, set := range groups {
		owner := set[0].Name()
		sigs := rrsigsForTypeAndOwner(allSigs, rrtype.NSEC3, owner)
		if len(sigs) == 0 {
			return fmt.Errorf("NSEC3 at %s lacks RRSIG", owner)
		}
		if err := w.verifyRRsetWithKeys(set, sigs, parentKeys); err != nil {
			return fmt.Errorf("NSEC3 rrsig at %s: %w", owner, err)
		}
	}
	return nil
}

// validateNSECNXDomain implements the RFC 4035 §5.4 NSEC NXDOMAIN proof.
// Two NSEC records are required:
//
//  1. A "covering" NSEC for qname: owner < qname < next in canonical
//     order (RFC 4034 §6.1), proving qname does not exist.
//  2. A second NSEC that proves no wildcard at the closest encloser
//     could have synthesised an answer — that is, an NSEC covering
//     "*.<closest_encloser>". An NSEC whose owner is exactly the
//     wildcard means the wildcard exists, in which case NXDOMAIN
//     should not have been the response and we treat the proof as
//     bogus.
//
// Without check (2) a malicious authoritative for a zone that has a
// wildcard could suppress the wildcard answer and serve NXDOMAIN with a
// single covering NSEC, having it validate as Secure. RFC 4035 §5.4
// makes the wildcard-non-existence proof mandatory; earlier versions of
// this function only enforced check (1).
func (w *walker) validateNSECNXDomain(qname wire.Name, parentKeys []rdata.DNSKEY, msg wire.Message) error {
	nsecRRs := allNSEC(msg.Authorities())
	if len(nsecRRs) == 0 {
		return fmt.Errorf("no NSEC in authority")
	}
	// Group NSEC records and require every group to be signature-verified.
	// Skipping a group with no RRSIG would let a forged NSEC inserted
	// alongside a legitimate one fabricate the wildcard side of the proof
	// (the cover/wildcard scans below iterate every NSEC). Mirror the
	// fail-closed shape used by verifyNSEC3Set.
	groups := validatorbb.GroupRecordsByOwner(nsecRRs)
	allSigs := extractRRSIGs(msg.Authorities())
	for _, set := range groups {
		owner := set[0].Name()
		sigs := rrsigsForTypeAndOwner(allSigs, rrtype.NSEC, owner)
		if len(sigs) == 0 {
			return fmt.Errorf("NSEC at %s lacks RRSIG", owner)
		}
		if err := w.verifyRRsetWithKeys(set, sigs, parentKeys); err != nil {
			return fmt.Errorf("NSEC rrsig at %s: %w", owner, err)
		}
	}
	// 1. Find a covering NSEC for qname and capture its bounds for the
	//    closest-encloser derivation.
	var (
		coverOwner wire.Name
		coverNext  wire.Name
		covered    bool
	)
	for _, r := range nsecRRs {
		nsec, ok := wire.RDataAs[rdata.NSEC](r)
		if !ok {
			continue
		}
		if validatorbb.NameCoveredBy(qname, r.Name(), nsec.NextDomainName()) {
			coverOwner = r.Name()
			coverNext = nsec.NextDomainName()
			covered = true
			break
		}
	}
	if !covered {
		return fmt.Errorf("no NSEC covers %s", qname)
	}
	// 2. Closest encloser is the deeper of LCA(qname, coverOwner) and
	//    LCA(qname, coverNext). Both NSEC bounds bracket qname in
	//    canonical order, so each common ancestor is itself an existing
	//    name in the zone; the deeper one is the closest encloser.
	encA := validatorbb.LongestCommonAncestor(qname, coverOwner)
	encB := validatorbb.LongestCommonAncestor(qname, coverNext)
	encloser := encA
	if encB.NumLabels() > encloser.NumLabels() {
		encloser = encB
	}
	wildcard, err := validatorbb.WildcardOf(encloser)
	if err != nil {
		return fmt.Errorf("validator: derive wildcard at %s: %w", encloser, err)
	}
	for _, r := range nsecRRs {
		nsec, ok := wire.RDataAs[rdata.NSEC](r)
		if !ok {
			continue
		}
		if r.Name().Equal(wildcard) {
			// The wildcard exists; NXDOMAIN should have been a wildcard
			// expansion. Treat the proof as bogus.
			return fmt.Errorf("validator: NSEC proves wildcard %s exists; NXDOMAIN bogus", wildcard)
		}
		if validatorbb.NameCoveredBy(wildcard, r.Name(), nsec.NextDomainName()) {
			return nil
		}
	}
	return fmt.Errorf("validator: no NSEC covers wildcard %s for closest encloser %s", wildcard, encloser)
}

// wildcardSynthLabels reports whether sigs indicates the answer was
// synthesised from a wildcard. RFC 4034 §3.1.3 — the RRSIG Labels
// field counts the labels of the original RRSIG owner (the wildcard),
// not counting the null root label nor the leading "*" label. So
// sig.Labels() < qname.NumLabels() is the wildcard signal; the
// difference identifies the closest-encloser label count. When more
// than one sig matches, the smallest Labels() value identifies the
// shallowest wildcard in play (an attacker can't downgrade the proof
// requirement by also stuffing a non-wildcard sig into the answer
// section, because we still need the proof for the wildcard sig).
func wildcardSynthLabels(qname wire.Name, sigs []rdata.RRSIG) (encloserLabels int, wildcard bool) {
	encloserLabels = -1
	for _, sig := range sigs {
		l := int(sig.Labels())
		if l < qname.NumLabels() {
			if !wildcard || l < encloserLabels {
				encloserLabels = l
				wildcard = true
			}
		}
	}
	return encloserLabels, wildcard
}

// validateWildcardNextCloser implements the RFC 4035 §5.3.4
// requirement that a wildcard-synthesised positive answer be
// accompanied by NSEC or NSEC3 proving qname does not exist directly
// in the zone.
//
//   - NSEC: any NSEC whose interval covers qname suffices (qname is
//     proven non-existent at its own label count, which forces
//     wildcard synthesis as the only legitimate response shape).
//   - NSEC3: a covering NSEC3 for the next-closer name (qname
//     truncated to encloserLabels+1) per §5.3.4 read in conjunction
//     with RFC 5155 §7.2.6.
func (w *walker) validateWildcardNextCloser(qname wire.Name, encloserLabels int, parentKeys []rdata.DNSKEY, msg wire.Message) error {
	nsecRRs := allNSEC(msg.Authorities())
	nsec3RRs := recordsOfType3(msg.Authorities())
	if len(nsecRRs) == 0 && len(nsec3RRs) == 0 {
		return fmt.Errorf("no NSEC or NSEC3 in authority")
	}
	if len(nsecRRs) > 0 {
		groups := validatorbb.GroupRecordsByOwner(nsecRRs)
		allSigs := extractRRSIGs(msg.Authorities())
		for _, set := range groups {
			owner := set[0].Name()
			sigs := rrsigsForTypeAndOwner(allSigs, rrtype.NSEC, owner)
			if len(sigs) == 0 {
				return fmt.Errorf("NSEC at %s lacks RRSIG", owner)
			}
			if err := w.verifyRRsetWithKeys(set, sigs, parentKeys); err != nil {
				return fmt.Errorf("NSEC rrsig at %s: %w", owner, err)
			}
		}
		for _, r := range nsecRRs {
			nsec, ok := wire.RDataAs[rdata.NSEC](r)
			if !ok {
				continue
			}
			if validatorbb.NameCoveredBy(qname, r.Name(), nsec.NextDomainName()) {
				return nil
			}
		}
		return fmt.Errorf("no NSEC covers qname %s", qname)
	}
	if err := w.verifyNSEC3Set(nsec3RRs, msg.Authorities(), parentKeys); err != nil {
		return fmt.Errorf("NSEC3 rrsig: %w", err)
	}
	params, ok := extractNSEC3Params(nsec3RRs)
	if !ok {
		return fmt.Errorf("inconsistent NSEC3 params")
	}
	nextCloserLabels := encloserLabels + 1
	if nextCloserLabels > qname.NumLabels() {
		return fmt.Errorf("encloser deeper than qname (%d > %d)", encloserLabels, qname.NumLabels())
	}
	nextCloser := validatorbb.TruncateNameTo(qname, nextCloserLabels)
	if _, covered := nsec3Cover(nextCloser, params, nsec3RRs); !covered {
		return fmt.Errorf("no NSEC3 covers next-closer %s", nextCloser)
	}
	return nil
}

// validateNoData returns Secure with empty records when a NoData answer is
// validly proven by NSEC or NSEC3; Bogus otherwise.
func (w *walker) validateNoData(qname wire.Name, qtype rrtype.Type, parentKeys []rdata.DNSKEY, msg wire.Message, chain []ChainStep) (Answer, error) {
	// Try NSEC first.
	if ans, ok := w.validateNoDataNSEC(qname, qtype, parentKeys, msg, chain); ok {
		return ans, nil
	}
	// Fall through to NSEC3.
	if ans, ok := w.validateNoDataNSEC3(qname, qtype, parentKeys, msg, chain); ok {
		return ans, nil
	}
	return w.bogus(qname, qtype, chain, fmt.Errorf("validator: NoData missing NSEC/NSEC3 proof"))
}

func (w *walker) validateNoDataNSEC(qname wire.Name, qtype rrtype.Type, parentKeys []rdata.DNSKEY, msg wire.Message, chain []ChainStep) (Answer, bool) {
	allNSECs := allNSEC(msg.Authorities())
	if len(allNSECs) == 0 {
		return nil, false
	}
	// Verify every NSEC group; fail closed if any group lacks signatures
	// or fails verification, otherwise the ENT scan below could rely on
	// an unsigned record.
	groups := validatorbb.GroupRecordsByOwner(allNSECs)
	allSigs := extractRRSIGs(msg.Authorities())
	for _, set := range groups {
		owner := set[0].Name()
		sigs := rrsigsForTypeAndOwner(allSigs, rrtype.NSEC, owner)
		if len(sigs) == 0 {
			return nil, false
		}
		if err := w.verifyRRsetWithKeys(set, sigs, parentKeys); err != nil {
			return nil, false
		}
	}

	// Case 1 (RFC 4035 §3.1.3.1): NSEC at owner==qname proves qtype absence
	// via its type bitmap.
	for _, r := range allNSECs {
		if !r.Name().Equal(qname) {
			continue
		}
		nsec, ok := wire.RDataAs[rdata.NSEC](r)
		if !ok {
			continue
		}
		if !bitmapHas(nsec.Types(), qtype) {
			return &answer{
				result:  Secure,
				records: nil,
				rcode:   wire.RCODENoError,
				chain:   chain,
			}, true
		}
	}

	// Case 2 (RFC 4035 §3.1.3.4 / RFC 7129 §5.5): qname is an Empty
	// Non-Terminal. Proven by an NSEC whose owner is a proper ancestor
	// of qname AND whose NextDomainName is a strict descendant of qname
	// — qname must exist as an interior name to be skipped over by the
	// chain — and an ENT has no records of any type, so NoData for
	// qtype follows automatically.
	//
	// The owner-is-ancestor check is non-negotiable: without it, a
	// hostile authoritative for the same zone could synthesise an NSEC
	// whose Next happens to be a subdomain of qname but whose owner
	// has no relation, which would falsely satisfy "ENT NoData" for
	// names that should NXDOMAIN. The signature-bound nature of the
	// NSEC limits the attack surface to a compromised or malicious
	// in-zone signer, but the structural check costs us nothing.
	for _, r := range allNSECs {
		nsec, ok := wire.RDataAs[rdata.NSEC](r)
		if !ok {
			continue
		}
		next := nsec.NextDomainName()
		if next.Equal(qname) {
			continue
		}
		owner := r.Name()
		// Owner must be a strict ancestor of qname (not equal, not
		// unrelated). Using NameSuffixEqualOrSubdomain with owner ==
		// qname is filtered above by Case 1; here we additionally
		// require qname is a proper subdomain of owner.
		if !validatorbb.NameSuffixEqualOrSubdomain(qname, owner) || owner.Equal(qname) {
			continue
		}
		if validatorbb.NameSuffixEqualOrSubdomain(next, qname) {
			return &answer{
				result:  Secure,
				records: nil,
				rcode:   wire.RCODENoError,
				chain:   chain,
			}, true
		}
	}
	return nil, false
}

func (w *walker) validateNoDataNSEC3(qname wire.Name, qtype rrtype.Type, parentKeys []rdata.DNSKEY, msg wire.Message, chain []ChainStep) (Answer, bool) {
	nsec3RRs := recordsOfType3(msg.Authorities())
	if len(nsec3RRs) == 0 {
		return nil, false
	}
	if err := w.verifyNSEC3Set(nsec3RRs, msg.Authorities(), parentKeys); err != nil {
		return nil, false
	}
	// The zone for closest-encloser hashing must come from the
	// validated chain — not from the response's RRSIG signer. A
	// hostile authoritative for an unrelated signed zone could
	// otherwise craft a NoData response whose NSEC3 records hash
	// names under that other zone's apex; nsec3ProveDenial would
	// "find" matching hashes for the wrong namespace and report
	// Secure NoData. validateNegative already gets this right; the
	// NoData path was the asymmetric gap.
	zone := deepestSecureZone(chain)
	if !zone.IsValid() {
		return nil, false
	}
	respSigner := validatorbb.SignerOf(msg.Authorities())
	if respSigner.IsValid() && !validatorbb.NameSuffixEqualOrSubdomain(zone, respSigner) && !respSigner.Equal(zone) {
		return nil, false
	}
	res := nsec3ProveDenial(qname, qtype, zone, nsec3RRs)
	switch res.kind {
	case nsec3DenialNoData:
		return &answer{
			result:  Secure,
			records: nil,
			rcode:   wire.RCODENoError,
			chain:   chain,
		}, true
	case nsec3DenialIterationsExceeded:
		// RFC 9276 §3.2: high iteration count downgrades to Insecure.
		return &answer{
			result:  Insecure,
			records: msg.Answers(),
			rcode:   wire.RCODENoError,
			chain:   chain,
		}, true
	}
	return nil, false
}

// validateNegative classifies an NXDOMAIN/NoData response.
func (w *walker) validateNegative(qname wire.Name, qtype rrtype.Type, parentKeys []rdata.DNSKEY, msg wire.Message, chain []ChainStep) (Answer, error) {
	if msg.Flags().RCODE() != wire.RCODENXDomain {
		return w.validateNoData(qname, qtype, parentKeys, msg, chain)
	}
	// The zone for NSEC3 closest-encloser hashing must come from the
	// validated chain — not from the response's RRSIG signer name. A
	// hostile authoritative could otherwise smuggle a signer name from a
	// peer zone whose keys parentKeys do not authenticate.
	zone := deepestSecureZone(chain)
	if !zone.IsValid() {
		return w.bogus(qname, qtype, chain, fmt.Errorf("validator: no secure zone in chain"))
	}
	respSigner := validatorbb.SignerOf(msg.Authorities())
	if respSigner.IsValid() && !validatorbb.NameSuffixEqualOrSubdomain(zone, respSigner) && !respSigner.Equal(zone) {
		return w.bogus(qname, qtype, chain, fmt.Errorf("validator: NXDOMAIN signer %s not in chain (deepest secure zone %s)", respSigner, zone))
	}
	if err := w.validateNXDomain(qname, zone, parentKeys, msg); err != nil {
		if errors.Is(err, errInsecureNSEC3Iterations) {
			return &answer{
				result:  Insecure,
				records: nil,
				rcode:   wire.RCODENXDomain,
				chain:   chain,
				reason:  err,
			}, nil
		}
		return w.bogus(qname, qtype, chain, fmt.Errorf("validator: NXDOMAIN proof: %w", err))
	}
	return &answer{
		result:  Secure,
		records: nil,
		rcode:   wire.RCODENXDomain,
		chain:   chain,
	}, nil
}

// deepestSecureZone returns the zone of the deepest Secure step in chain.
// Returns the zero Name if no Secure step is present.
func deepestSecureZone(chain []ChainStep) wire.Name {
	for i := len(chain) - 1; i >= 0; i-- {
		if chain[i].Result() == Secure {
			return chain[i].Zone()
		}
	}
	return wire.Name{}
}

// signingAlgorithms returns the set of DNSSEC algorithms that the parent
// zone signaled via its DS rrset for the deepest secured zone in chain.
// RFC 6840 §5.11 requires every such algorithm to have a verifying RRSIG
// over each signed RRset; without this rule an attacker who can strip a
// stronger algorithm's RRSIGs effectively forces a downgrade to the
// weakest algorithm the zone advertises.
func signingAlgorithms(chain []ChainStep) map[rdata.DNSSECAlgorithm]struct{} {
	algs := map[rdata.DNSSECAlgorithm]struct{}{}
	for i := len(chain) - 1; i >= 0; i-- {
		if chain[i].Result() != Secure {
			continue
		}
		dss := chain[i].DSs()
		if len(dss) == 0 {
			continue
		}
		for _, ds := range dss {
			algs[ds.Algorithm()] = struct{}{}
		}
		return algs
	}
	return algs
}

// verifyRRsetAllAlgs implements RFC 6840 §5.11 algorithm-completeness on
// the answer rrset: for each algorithm in requiredAlgs, at least one
// matching RRSIG in sigs must validly cover set under one of keys. When
// requiredAlgs is empty (no DS algorithms tracked — typically the chain
// is anchored directly without traversing a DS step) the function falls
// back to "any RRSIG verifies" semantics.
func (w *walker) verifyRRsetAllAlgs(set []wire.Record, sigs []rdata.RRSIG, keys []rdata.DNSKEY, requiredAlgs map[rdata.DNSSECAlgorithm]struct{}) error {
	if len(requiredAlgs) == 0 {
		return w.verifyRRsetWithKeys(set, sigs, keys)
	}
	if len(set) == 0 {
		return fmt.Errorf("validator: empty rrset")
	}
	now := w.now()
	covered := map[rdata.DNSSECAlgorithm]struct{}{}
	// Walk every sig (do NOT pre-truncate to maxRRSIGsTry — that would
	// silently drop the only valid signature of a strong algorithm if
	// many weak-algorithm sigs sort before it). Cap the actual
	// dnssec.Verify calls instead.
	tries := 0
	for _, sig := range sigs {
		if _, need := requiredAlgs[sig.Algorithm()]; !need {
			continue
		}
		if _, done := covered[sig.Algorithm()]; done {
			continue
		}
		if !validatorbb.RRSIGValidNowWithSkew(sig, now, w.skew) {
			continue
		}
		for _, key := range keys {
			if dnssec.KeyTag(key) != sig.KeyTag() || key.Algorithm() != sig.Algorithm() {
				continue
			}
			tries++
			if tries > w.maxRRSIGsTry {
				break
			}
			if err := dnssec.Verify(set, sig, key); err == nil {
				covered[sig.Algorithm()] = struct{}{}
				break
			}
		}
		if tries > w.maxRRSIGsTry {
			break
		}
	}
	for alg := range requiredAlgs {
		if _, ok := covered[alg]; !ok {
			return fmt.Errorf("%w: alg %d not signed over answer", ErrAlgorithmIncomplete, alg)
		}
	}
	return nil
}

// verifyRRsetWithKeys verifies set against any of sigs using any of keys.
//
// Caps the cumulative number of dnssec.Verify calls at maxRRSIGsTry —
// without this, a zone publishing many DNSKEYs that share a single
// keytag drives `outer_sigs × N` Verify calls per signed RRset (cf.
// CVE-2023-50387 KeyTrap). The maxKeys cap on the DNSKEY rrset bounds
// N; this counter bounds the cross-product anyway.
//
// The cap is enforced as a budget on attempted Verify calls, NOT by
// pre-truncating sigs: pre-truncation silently drops a strong-algorithm
// RRSIG if many weak/invalid sigs sort before it (RFC 6840 §5.11
// algorithm-completeness for DNSKEY/DS internal callers).
func (w *walker) verifyRRsetWithKeys(set []wire.Record, sigs []rdata.RRSIG, keys []rdata.DNSKEY) error {
	if len(set) == 0 {
		return fmt.Errorf("validator: empty rrset")
	}
	now := w.now()
	var lastErr error
	tries := 0
	for _, sig := range sigs {
		if !validatorbb.RRSIGValidNowWithSkew(sig, now, w.skew) {
			lastErr = fmt.Errorf("RRSIG outside validity window")
			continue
		}
		for _, key := range keys {
			if dnssec.KeyTag(key) != sig.KeyTag() || key.Algorithm() != sig.Algorithm() {
				continue
			}
			tries++
			if tries > w.maxRRSIGsTry {
				if lastErr == nil {
					lastErr = ErrIterationLimit
				}
				return lastErr
			}
			err := dnssec.Verify(set, sig, key)
			if err == nil {
				return nil
			}
			lastErr = err
		}
		if tries > w.maxRRSIGsTry {
			break
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no RRSIG matched any key")
	}
	return lastErr
}

// indeterminate builds an Answer with Result=Indeterminate.
func (w *walker) indeterminate(_ wire.Name, _ rrtype.Type, err error, note string) Answer {
	if err == nil && note != "" {
		err = fmt.Errorf("validator: %s", note)
	}
	return &answer{result: Indeterminate, reason: err}
}

func (w *walker) bogus(_ wire.Name, _ rrtype.Type, chain []ChainStep, err error) (Answer, error) {
	// Wrap with ErrBogus so callers can branch on the umbrella sentinel
	// while errors.Is on the concrete underlying reason still works
	// (Go 1.20+ multi-%w preserves both chains).
	wrapped := fmt.Errorf("%w: %w", ErrBogus, err)
	a := &answer{result: Bogus, chain: chain, reason: wrapped}
	if w.bogusPolicy == BogusReturnAnswer {
		return a, nil
	}
	return a, wrapped
}
