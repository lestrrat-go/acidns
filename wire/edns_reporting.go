package wire

import (
	"fmt"
	"strconv"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// EDNSOptionReportChannel is the IANA-assigned Report-Channel option code
// (RFC 9567 §6).
const EDNSOptionReportChannel uint16 = 18

// NewReportChannel builds a Report-Channel EDNS option. agent is the
// reporting-agent domain the responder controls; clients construct their
// synthetic report query name underneath it.
func NewReportChannel(agent wirebb.Name) EDNSOption {
	p := wirebb.NewPacker(nil)
	p.NameUncompressed(agent)
	return ednsOption{code: EDNSOptionReportChannel, data: p.Bytes()}
}

// ReportChannelAgent decodes the agent-domain from a Report-Channel option.
// Returns false if o is not a Report-Channel option or is malformed.
func ReportChannelAgent(o EDNSOption) (wirebb.Name, bool) {
	if o.Code() != EDNSOptionReportChannel {
		return wirebb.Name{}, false
	}
	u := wirebb.NewUnpacker(o.Data())
	n, err := u.Name()
	if err != nil {
		return wirebb.Name{}, false
	}
	return n, true
}

// BuildErrorReportName constructs the synthetic query name a client uses to
// emit an Extended-DNS-Error report (RFC 9567 §7). The constructed name is
//
//	_er.<qtype>.<qname-labels>.<info-code>._er.<agent>
//
// qname must not be the root and must have at most ~250 octets after
// embedding (DNS name length limit).
func BuildErrorReportName(qname wirebb.Name, qtype rrtype.Type, infoCode ExtendedErrorCode, agent wirebb.Name) (wirebb.Name, error) {
	if !qname.IsValid() || qname.IsRoot() {
		return wirebb.Name{}, fmt.Errorf("%w: error-report qname must be non-root", ErrInvalidMessage)
	}
	if !agent.IsValid() {
		return wirebb.Name{}, fmt.Errorf("%w: error-report agent invalid", ErrInvalidMessage)
	}
	parts := []string{
		"_er",
		strconv.FormatUint(uint64(qtype), 10),
	}
	for label := range qname.Labels() {
		parts = append(parts, string(label))
	}
	parts = append(parts,
		strconv.FormatUint(uint64(infoCode), 10),
		"_er",
	)
	// Append the agent labels.
	for label := range agent.Labels() {
		parts = append(parts, string(label))
	}
	joined := joinLabels(parts)
	return wirebb.Parse(joined)
}

func joinLabels(parts []string) string {
	if len(parts) == 0 {
		return "."
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += "." + p
	}
	return out
}
