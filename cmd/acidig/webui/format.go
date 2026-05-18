package webui

import (
	"fmt"
	"strings"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// formatMessage builds the structured "dig-style" view of one DNS
// message — header, flags, counts, EDNS OPT pseudo-section, and the
// four record sections. Used for both the outgoing request and the
// incoming response.
//
// The OPT pseudo-RR (type 41 in the additional section) is stripped
// from the Additional list and rendered into its own EDNS field
// because dig presents it that way and because the parsed-out EDNS
// options (NSID, ECS, cookies, extended error) are far more useful
// than the opaque "OPT 0 0" line the generic record formatter would
// produce.
func formatMessage(m wire.Message) formattedMsg {
	f := m.Flags()
	out := formattedMsg{
		ID:        m.ID(),
		Opcode:    f.Opcode().String(),
		RCode:     f.RCODE().String(),
		Flags:     headerFlagList(f),
		Question:  formatQuestions(m.Questions()),
		Answer:    formatRecords(m.Answers()),
		Authority: formatRecords(m.Authorities()),
	}

	// Hide OPT from the additional dump and surface it as a dedicated
	// EDNS section, matching dig's "OPT PSEUDOSECTION" convention.
	var additional []wire.Record
	for _, rec := range m.Additionals() {
		if rec.Type() == rrtype.OPT {
			continue
		}
		additional = append(additional, rec)
	}
	out.Additional = formatRecords(additional)

	arcount := len(m.Additionals())
	if ed, ok := m.EDNS(); ok {
		out.EDNS = formatEDNS(ed)
		// dig's ARCOUNT line counts the OPT pseudo-RR alongside the
		// normal additionals; the wire library exposes EDNS as a
		// separate field, so add it back for display.
		arcount++
	}

	out.Counts = fmt.Sprintf("QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d",
		len(m.Questions()), len(m.Answers()), len(m.Authorities()), arcount)

	return out
}

func formatQuestions(qs []wire.Question) []string {
	out := make([]string, 0, len(qs))
	for _, q := range qs {
		out = append(out, fmt.Sprintf(";%s\t%s\t%s", q.Name(), q.Class(), q.Type()))
	}
	return out
}

// headerFlagList renders the standard DNS header flags as the lowercase
// short strings dig uses (qr, aa, tc, rd, ra, ad, cd).
func headerFlagList(f wire.Flags) []string {
	out := make([]string, 0, 7)
	if f.Response() {
		out = append(out, "qr")
	}
	if f.Authoritative() {
		out = append(out, "aa")
	}
	if f.Truncated() {
		out = append(out, "tc")
	}
	if f.RecursionDesired() {
		out = append(out, "rd")
	}
	if f.RecursionAvailable() {
		out = append(out, "ra")
	}
	if f.AuthenticData() {
		out = append(out, "ad")
	}
	if f.CheckingDisabled() {
		out = append(out, "cd")
	}
	return out
}

// formatEDNS renders the OPT pseudo-RR in dig's PSEUDOSECTION shape:
// the version + flag-bit header line, the advertised UDP payload size,
// and one line per recognised option with its decoded payload.
func formatEDNS(e wire.EDNS) []string {
	out := make([]string, 0, 1+len(e.Options()))
	doFlag := "do=0"
	if e.DO() {
		doFlag = "do=1"
	}
	out = append(out, fmt.Sprintf("; EDNS: version: %d, %s; udp: %d; extRCODE: %d",
		e.Version(), doFlag, e.UDPSize(), e.ExtendedRCODE()))
	for _, opt := range e.Options() {
		out = append(out, "; "+formatEDNSOption(opt))
	}
	return out
}

func formatEDNSOption(o wire.EDNSOption) string {
	switch o.Code() {
	case wire.EDNSOptionNSID:
		if id, ok := wire.NSIDIdentifier(o); ok {
			return fmt.Sprintf("NSID: %q", id)
		}
	case wire.EDNSOptionClientSubnet:
		if pfx, scope, ok := wire.ClientSubnet(o); ok {
			return fmt.Sprintf("CLIENT-SUBNET: %s/%d", pfx, scope)
		}
	case wire.EDNSOptionCookie:
		if client, server, ok := wire.Cookies(o); ok {
			if len(server) == 0 {
				return fmt.Sprintf("COOKIE: %x", client)
			}
			return fmt.Sprintf("COOKIE: %x %x", client, server)
		}
	case wire.EDNSOptionTCPKeepalive:
		if d, ok := wire.TCPKeepaliveTimeout(o); ok {
			return fmt.Sprintf("TCP-KEEPALIVE: %s", d)
		}
		return "TCP-KEEPALIVE: (no timeout)"
	case wire.EDNSOptionExpire:
		if secs, ok := wire.EDNSExpireSeconds(o); ok {
			return fmt.Sprintf("EXPIRE: %ds", secs)
		}
	case wire.EDNSOptionExtendedDNS:
		if code, txt, ok := wire.ExtendedError(o); ok {
			if txt == "" {
				return fmt.Sprintf("EDE: %d", code)
			}
			return fmt.Sprintf("EDE: %d (%q)", code, txt)
		}
	case wire.EDNSOptionPadding:
		return fmt.Sprintf("PADDING: %d bytes", len(o.Data()))
	}
	return fmt.Sprintf("OPT-%d: %x", o.Code(), o.Data())
}

func formatRecords(in []wire.Record) []string {
	out := make([]string, 0, len(in))
	for _, rec := range in {
		out = append(out, formatRecord(rec))
	}
	return out
}

func formatRecord(rec wire.Record) string {
	return fmt.Sprintf("%s\t%d\t%s\t%s\t%s",
		rec.Name(), int(rec.TTL().Seconds()), rec.Class(), rec.Type(), formatRData(rec.RData()))
}

// formatRData renders an rdata payload as text. Mirrors the matching
// helper in cmd/acidig/main.go so the web UI presents records the
// same way the CLI does.
func formatRData(rd rdata.RData) string {
	switch v := rd.(type) {
	case rdata.A:
		return v.Addr().String()
	case rdata.AAAA:
		return v.Addr().String()
	case rdata.CNAME:
		return v.Target().String()
	case rdata.NS:
		return v.Target().String()
	case rdata.PTR:
		return v.Target().String()
	case rdata.MX:
		return fmt.Sprintf("%d %s", v.Preference(), v.Exchange())
	case rdata.TXT:
		var parts []string
		for _, s := range v.Strings() {
			parts = append(parts, fmt.Sprintf("%q", s))
		}
		return strings.Join(parts, " ")
	case rdata.SOA:
		return fmt.Sprintf("%s %s %d %d %d %d %d",
			v.MName(), v.RName(), v.Serial(),
			int(v.Refresh().Seconds()), int(v.Retry().Seconds()),
			int(v.Expire().Seconds()), int(v.Minimum().Seconds()))
	case rdata.SRV:
		return fmt.Sprintf("%d %d %d %s", v.Priority(), v.Weight(), v.Port(), v.Target())
	case rdata.CAA:
		return fmt.Sprintf("%d %s %q", v.Flags(), v.Tag(), v.Value())
	case rdata.SVCB:
		return formatSvcbBody(v.Priority(), v.Target().String(), v.Params())
	case rdata.HTTPS:
		return formatSvcbBody(v.Priority(), v.Target().String(), v.Params())
	case rdata.Unknown:
		return fmt.Sprintf("\\# %d (opaque)", len(v.Bytes()))
	default:
		return fmt.Sprintf("(%s)", rd.Type())
	}
}

func formatSvcbBody(priority uint16, target string, params []rdata.SVCBParam) string {
	var out strings.Builder
	fmt.Fprintf(&out, "%d %s", priority, target)
	for _, p := range params {
		fmt.Fprintf(&out, " key%d=%x", p.Key(), p.Value())
	}
	return out.String()
}
