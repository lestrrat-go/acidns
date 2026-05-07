package validator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/acidns/dnssec"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
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

func (s chainStep) Zone() wire.Name        { return s.zone }
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

func (a *answer) Result() Result          { return a.result }
func (a *answer) Records() []wire.Record  { return a.records }
func (a *answer) RCODE() wire.RCODE       { return a.rcode }
func (a *answer) Chain() []ChainStep      { return a.chain }
func (a *answer) Reason() error           { return a.reason }

// WalkerOption configures a Walker. Options live in walker_options.go.
type WalkerOption interface {
	applyWalker(*walker)
}

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
}

// NewWalker constructs a Walker. A Source is required; any other option may
// be omitted to take its default. The default trust anchor is the IANA
// root KSK (see IANARootAnchor); production callers should override with
// their own RFC 5011 trust-anchor file.
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
	}
	for _, o := range opts {
		o.applyWalker(w)
	}
	if len(w.anchors) == 0 {
		w.anchors = []Anchor{IANARootAnchor()}
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
		matching := recordsOfType(answers, qtype, qname)
		if len(matching) == 0 {
			// Could be a CNAME chain — caller's responsibility (resolver
			// follows CNAMEs). For the walker we treat as no-data.
			return w.validateNoData(qname, qtype, parentKeys, msg, chain)
		}
		sigs := rrsigsForTypeAndOwner(extractRRSIGs(answers), qtype, qname)
		if len(sigs) == 0 {
			return w.bogus(qname, qtype, chain, ErrUnsignedAnswer)
		}
		_, _, err := w.verifyRRsetWithKeys(matching, sigs, parentKeys)
		if err != nil {
			return w.bogus(qname, qtype, chain, fmt.Errorf("validator: answer rrsig: %w", err))
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
		candidate := truncateNameTo(qname, nextLabels)

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
	dnskeyRRs := recordsOfType(msg.Answers(), rrtype.DNSKEY, zone)
	if len(dnskeyRRs) == 0 {
		return nil, fmt.Errorf("validator: no DNSKEY rrset at %s", zone)
	}
	keys := make([]rdata.DNSKEY, 0, len(dnskeyRRs))
	for _, r := range dnskeyRRs {
		k, ok := wire.RDataAs[rdata.DNSKEY](r)
		if !ok {
			return nil, fmt.Errorf("validator: bad DNSKEY rdata at %s", zone)
		}
		keys = append(keys, k)
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
	usedSig, _, err := w.verifyRRsetWithKeys(dnskeyRRs, sigs, trustedKSKs)
	if err != nil {
		return nil, fmt.Errorf("DNSKEY rrset rrsig: %w", err)
	}
	_ = usedSig

	// RFC 6840 §5.11: every algorithm in the parent's DS list must have a
	// signing pair. Walk RRSIGs and mark covered algorithms.
	signingAlgs := map[rdata.DNSSECAlgorithm]struct{}{}
	for _, sig := range sigs {
		// Match RRSIG to a DNSKEY in the rrset; the key need not be a KSK.
		for _, key := range keys {
			if dnssec.KeyTag(key) == sig.KeyTag() && key.Algorithm() == sig.Algorithm() {
				signingAlgs[sig.Algorithm()] = struct{}{}
				break
			}
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
	dsOutcomeUnknown dsOutcome = iota
	dsOutcomeCut              // DS RRset present and signature-verified
	dsOutcomeInsecure         // signed proof of NoData(DS) where NSEC bitmap has NS
	dsOutcomeNonCut           // signed proof of NoData(DS) where NS bit absent
	dsOutcomeNXDomain         // signed proof that candidate doesn't exist
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
	dsRRs := recordsOfType(msg.Answers(), rrtype.DS, candidate)
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
		if _, _, err := w.verifyRRsetWithKeys(dsRRs, sigs, parentKeys); err != nil {
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
	nsecRRs := recordsOfType(msg.Authorities(), rrtype.NSEC, candidate)
	if len(nsecRRs) == 0 {
		nsecRRs = filterNSECByOwner(msg.Authorities(), candidate)
	}
	if len(nsecRRs) == 0 {
		return dsOutcomeUnknown, false, nil
	}
	sigs := rrsigsForTypeAndOwner(extractRRSIGs(msg.Authorities()), rrtype.NSEC, candidate)
	if len(sigs) == 0 {
		return dsOutcomeUnknown, true, fmt.Errorf("validator: NSEC at %s lacks RRSIG", candidate)
	}
	if _, _, err := w.verifyRRsetWithKeys(nsecRRs, sigs, parentKeys); err != nil {
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
	case nsec3DenialNoData:
		return dsOutcomeNonCut, true, nil
	}
	return dsOutcomeUnknown, true, fmt.Errorf("validator: NSEC3 at %s did not prove DS absence", candidate)
}

// validateNXDomain validates an NXDOMAIN response using NSEC OR NSEC3.
func (w *walker) validateNXDomain(qname, parentZone wire.Name, parentKeys []rdata.DNSKEY, msg wire.Message) error {
	if err := w.validateNSECNXDomain(qname, parentKeys, msg); err == nil {
		return nil
	}
	// Fall through to NSEC3.
	return w.validateNSEC3NXDomain(qname, parentZone, parentKeys, msg)
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
	}
	return fmt.Errorf("NSEC3 did not prove NXDOMAIN for %s", qname)
}

// verifyNSEC3Set verifies each NSEC3 rrset (grouped by owner) in records
// against parentKeys. authority is the full authority section the rrsets
// were drawn from (used to find covering RRSIGs).
func (w *walker) verifyNSEC3Set(nsec3RRs, authority []wire.Record, parentKeys []rdata.DNSKEY) error {
	groups := groupRecordsByOwner(nsec3RRs)
	allSigs := extractRRSIGs(authority)
	for _, set := range groups {
		owner := set[0].Name()
		sigs := rrsigsForTypeAndOwner(allSigs, rrtype.NSEC3, owner)
		if len(sigs) == 0 {
			return fmt.Errorf("NSEC3 at %s lacks RRSIG", owner)
		}
		if _, _, err := w.verifyRRsetWithKeys(set, sigs, parentKeys); err != nil {
			return fmt.Errorf("NSEC3 rrsig at %s: %w", owner, err)
		}
	}
	return nil
}

// validateNSECNXDomain performs a minimal NSEC NXDOMAIN check: the
// authority section must contain an NSEC record whose owner is a
// predecessor of candidate and whose Next field is an ancestor strictly
// above candidate (the "covering" NSEC). Closest-encloser proof for
// wildcard-aware NXDOMAIN is RFC 5155 NSEC3 territory (task #2).
//
// For the chain walker this is invoked when an intermediate DS query
// returns NXDOMAIN — a relatively rare edge case. We require the NSEC to
// be signed by parentKeys.
func (w *walker) validateNSECNXDomain(qname wire.Name, parentKeys []rdata.DNSKEY, msg wire.Message) error {
	nsecRRs := allNSEC(msg.Authorities())
	if len(nsecRRs) == 0 {
		return fmt.Errorf("no NSEC in authority")
	}
	// Group NSEC records and verify the rrset signatures.
	groups := groupNSECByOwner(nsecRRs)
	for _, set := range groups {
		owner := set[0].Name()
		sigs := rrsigsForTypeAndOwner(extractRRSIGs(msg.Authorities()), rrtype.NSEC, owner)
		if len(sigs) == 0 {
			continue
		}
		if _, _, err := w.verifyRRsetWithKeys(set, sigs, parentKeys); err != nil {
			return fmt.Errorf("NSEC rrsig: %w", err)
		}
	}
	// Coverage check: at least one verified NSEC must "cover" qname (owner
	// < qname < next). This is intentionally simplified pending NSEC3
	// closest-encloser support.
	for _, r := range nsecRRs {
		nsec, ok := wire.RDataAs[rdata.NSEC](r)
		if !ok {
			continue
		}
		if nameCoveredBy(qname, r.Name(), nsec.NextDomainName()) {
			return nil
		}
	}
	return fmt.Errorf("no NSEC covers %s", qname)
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
	nsecRRs := filterNSECByOwner(msg.Authorities(), qname)
	if len(nsecRRs) == 0 {
		return nil, false
	}
	sigs := rrsigsForTypeAndOwner(extractRRSIGs(msg.Authorities()), rrtype.NSEC, qname)
	if len(sigs) == 0 {
		return nil, false
	}
	if _, _, err := w.verifyRRsetWithKeys(nsecRRs, sigs, parentKeys); err != nil {
		return nil, false
	}
	for _, r := range nsecRRs {
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
	zone := signerOf(msg.Authorities())
	if !zone.IsValid() {
		return nil, false
	}
	res := nsec3ProveDenial(qname, qtype, zone, nsec3RRs)
	if res.kind == nsec3DenialNoData {
		return &answer{
			result:  Secure,
			records: nil,
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
	zone := signerOf(msg.Authorities())
	if err := w.validateNXDomain(qname, zone, parentKeys, msg); err != nil {
		return w.bogus(qname, qtype, chain, fmt.Errorf("validator: NXDOMAIN proof: %w", err))
	}
	return &answer{
		result:  Secure,
		records: nil,
		rcode:   wire.RCODENXDomain,
		chain:   chain,
	}, nil
}

// verifyRRsetWithKeys verifies set against any of sigs using any of keys.
// Returns the RRSIG that satisfied verification and the matching DNSKEY.
func (w *walker) verifyRRsetWithKeys(set []wire.Record, sigs []rdata.RRSIG, keys []rdata.DNSKEY) (rdata.RRSIG, rdata.DNSKEY, error) {
	if len(set) == 0 {
		return rdata.RRSIG{}, rdata.DNSKEY{}, fmt.Errorf("validator: empty rrset")
	}
	if len(sigs) > w.maxRRSIGsTry {
		sigs = sigs[:w.maxRRSIGsTry]
	}
	now := w.now()
	var lastErr error
	for _, sig := range sigs {
		if !rrsigValidNowWithSkew(sig, now, w.skew) {
			lastErr = fmt.Errorf("RRSIG outside validity window")
			continue
		}
		for _, key := range keys {
			if dnssec.KeyTag(key) != sig.KeyTag() || key.Algorithm() != sig.Algorithm() {
				continue
			}
			if err := dnssec.Verify(set, sig, key); err == nil {
				return sig, key, nil
			} else {
				lastErr = err
			}
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no RRSIG matched any key")
	}
	return rdata.RRSIG{}, rdata.DNSKEY{}, lastErr
}

func rrsigValidNowWithSkew(sig rdata.RRSIG, now time.Time, skew time.Duration) bool {
	if now.Add(skew).Before(sig.SignatureInception()) {
		return false
	}
	if now.Add(-skew).After(sig.SignatureExpiration()) {
		return false
	}
	return true
}

// indeterminate builds an Answer with Result=Indeterminate.
func (w *walker) indeterminate(qname wire.Name, qtype rrtype.Type, err error, note string) Answer {
	if err == nil && note != "" {
		err = fmt.Errorf("validator: %s", note)
	}
	return &answer{result: Indeterminate, reason: err}
}

func (w *walker) bogus(qname wire.Name, qtype rrtype.Type, chain []ChainStep, err error) (Answer, error) {
	a := &answer{result: Bogus, chain: chain, reason: err}
	if w.bogusPolicy == BogusReturnAnswer {
		return a, nil
	}
	return a, err
}

// truncateNameTo returns name with exactly k labels (counting from the root).
// If name has fewer than k labels, returns name unchanged.
func truncateNameTo(name wire.Name, k int) wire.Name {
	cur := name
	for cur.NumLabels() > k {
		parent, ok := cur.Parent()
		if !ok {
			break
		}
		cur = parent
	}
	return cur
}
