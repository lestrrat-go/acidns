package zonefile

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// hexDecode tolerates whitespace within a hex string. Master files
// commonly split a long DS digest across multiple parens-quoted lines
// for legibility.
func hexDecode(s string) ([]byte, error) {
	clean := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
	return hex.DecodeString(clean)
}

// b64Decode tolerates whitespace within a base64 string for the same
// reason hexDecode does (DNSKEY public keys span multiple lines).
func b64Decode(s string) ([]byte, error) {
	clean := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
	return base64.StdEncoding.DecodeString(clean)
}

type parser struct {
	lex        *lexer
	origin     wire.Name
	defaultTTL int64
	prevName   wire.Name
	records    []wire.Record
}

func newParser(r io.Reader, c config) *parser {
	return &parser{
		lex:        newLexer(r),
		origin:     c.origin,
		defaultTTL: c.defaultTTL,
	}
}

func (p *parser) run() error {
	for {
		// Collect tokens for one logical line.
		fields, leadingWS, eof, err := p.readLine()
		if err != nil {
			return err
		}
		if eof && len(fields) == 0 {
			return nil
		}
		if len(fields) == 0 {
			continue
		}
		if err := p.handleLine(fields, leadingWS); err != nil {
			return err
		}
	}
}

// fieldTok carries text plus quoted-flag for downstream type-specific
// parsing (TXT cares about quoted boundaries; rrtypes that don't quote do
// not).
type fieldTok struct {
	text   string
	quoted bool
	line   int
}

func (p *parser) readLine() ([]fieldTok, bool, bool, error) {
	var out []fieldTok
	leading := false
	first := true
	for {
		t, lws, err := p.lex.next()
		if err != nil {
			return nil, false, false, err
		}
		switch t.kind {
		case tokEOF:
			return out, false, true, nil
		case tokEOL:
			return out, leading, false, nil
		default:
			if first {
				leading = lws
				first = false
			}
			out = append(out, fieldTok{text: t.text, quoted: t.kind == tokQuoted, line: t.line})
		}
	}
}

func (p *parser) handleLine(fields []fieldTok, leadingWS bool) error {
	first := fields[0].text

	if strings.HasPrefix(first, "$") {
		return p.handleDirective(fields)
	}

	var ownerTok *fieldTok
	lineNum := fields[0].line
	if leadingWS {
		// blank owner: re-use previous name
		if !p.prevName.IsValid() {
			return fmt.Errorf("line %d: blank owner with no preceding RR", lineNum)
		}
	} else {
		ownerTok = &fields[0]
		fields = fields[1:]
	}

	owner, err := p.resolveName(ownerOrPrev(ownerTok, p.prevName))
	if err != nil {
		return fmt.Errorf("line %d: %w", lineNum, err)
	}

	// [TTL] [CLASS] TYPE RDATA   — TTL and CLASS are interchangeable in any
	// order before TYPE.
	ttl := p.defaultTTL
	class := rrtype.ClassIN
	for len(fields) > 0 {
		tok := fields[0].text
		if class != rrtype.ClassIN {
			break
		}
		if t, err := strconv.ParseInt(tok, 10, 64); err == nil {
			ttl = t
			fields = fields[1:]
			continue
		}
		if c, ok := parseClass(tok); ok {
			class = c
			fields = fields[1:]
			continue
		}
		break
	}
	if len(fields) == 0 {
		return fmt.Errorf("line %d: missing RR type", lineNum)
	}
	t, ok := rrtype.Parse(fields[0].text)
	if !ok {
		return fmt.Errorf("line %d: unknown RR type %q", fields[0].line, fields[0].text)
	}
	rest := fields[1:]
	if ttl < 0 {
		return fmt.Errorf("line %d: TTL not set (use $TTL)", fields[0].line)
	}
	rd, err := p.parseRData(t, rest)
	if err != nil {
		return fmt.Errorf("line %d: %w", fields[0].line, err)
	}
	rec := wire.NewRecordClass(owner, class, time.Duration(ttl)*time.Second, rd)
	p.records = append(p.records, rec)
	p.prevName = owner
	return nil
}

func ownerOrPrev(tok *fieldTok, _ wire.Name) string {
	if tok == nil {
		return ""
	}
	return tok.text
}

func (p *parser) resolveName(s string) (wire.Name, error) {
	if s == "" {
		return p.prevName, nil
	}
	if s == "@" {
		if !p.origin.IsValid() {
			return wire.Name{}, fmt.Errorf("@ used before $ORIGIN")
		}
		return p.origin, nil
	}
	if strings.HasSuffix(s, ".") {
		return wire.ParseName(s)
	}
	if !p.origin.IsValid() {
		return wire.Name{}, fmt.Errorf("relative name %q with no $ORIGIN", s)
	}
	full := s + "." + p.origin.String()
	return wire.ParseName(full)
}

func (p *parser) handleDirective(fields []fieldTok) error {
	switch strings.ToUpper(fields[0].text) {
	case "$ORIGIN":
		if len(fields) != 2 {
			return fmt.Errorf("line %d: $ORIGIN needs one argument", fields[0].line)
		}
		n, err := wire.ParseName(fields[1].text)
		if err != nil {
			return fmt.Errorf("line %d: $ORIGIN: %w", fields[0].line, err)
		}
		p.origin = n
		return nil
	case "$TTL":
		if len(fields) != 2 {
			return fmt.Errorf("line %d: $TTL needs one argument", fields[0].line)
		}
		v, err := strconv.ParseInt(fields[1].text, 10, 64)
		if err != nil {
			return fmt.Errorf("line %d: $TTL: %w", fields[0].line, err)
		}
		p.defaultTTL = v
		return nil
	default:
		return fmt.Errorf("line %d: unknown directive %s", fields[0].line, fields[0].text)
	}
}

func parseClass(s string) (rrtype.Class, bool) {
	switch strings.ToUpper(s) {
	case "IN":
		return rrtype.ClassIN, true
	case "CH":
		return rrtype.ClassCH, true
	case "HS":
		return rrtype.ClassHS, true
	case "ANY":
		return rrtype.ClassANY, true
	case "NONE":
		return rrtype.ClassNONE, true
	}
	return 0, false
}

func (p *parser) parseRData(t rrtype.Type, fields []fieldTok) (rdata.RData, error) {
	switch t {
	case rrtype.A:
		if len(fields) != 1 {
			return nil, fmt.Errorf("rdata A: expected 1 field, got %d", len(fields))
		}
		ip, err := netip.ParseAddr(fields[0].text)
		if err != nil {
			return nil, fmt.Errorf("rdata A: %w", err)
		}
		if !ip.Is4() {
			return nil, fmt.Errorf("rdata A: not an IPv4 address: %s", fields[0].text)
		}
		return rdata.NewA(ip)
	case rrtype.AAAA:
		if len(fields) != 1 {
			return nil, fmt.Errorf("AAAA: expected 1 field, got %d", len(fields))
		}
		ip, err := netip.ParseAddr(fields[0].text)
		if err != nil {
			return nil, fmt.Errorf("AAAA: %w", err)
		}
		if !ip.Is6() {
			return nil, fmt.Errorf("AAAA: not an IPv6 address: %s", fields[0].text)
		}
		return rdata.NewAAAA(ip)
	case rrtype.NS:
		if len(fields) != 1 {
			return nil, fmt.Errorf("NS: expected 1 field")
		}
		n, err := p.resolveName(fields[0].text)
		if err != nil {
			return nil, err
		}
		return rdata.NewNS(n)
	case rrtype.CNAME:
		if len(fields) != 1 {
			return nil, fmt.Errorf("CNAME: expected 1 field")
		}
		n, err := p.resolveName(fields[0].text)
		if err != nil {
			return nil, err
		}
		return rdata.NewCNAME(n)
	case rrtype.PTR:
		if len(fields) != 1 {
			return nil, fmt.Errorf("PTR: expected 1 field")
		}
		n, err := p.resolveName(fields[0].text)
		if err != nil {
			return nil, err
		}
		return rdata.NewPTR(n)
	case rrtype.MX:
		if len(fields) != 2 {
			return nil, fmt.Errorf("MX: expected 2 fields")
		}
		pref, err := strconv.ParseUint(fields[0].text, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("MX preference: %w", err)
		}
		n, err := p.resolveName(fields[1].text)
		if err != nil {
			return nil, err
		}
		return rdata.NewMX(uint16(pref), n)
	case rrtype.TXT:
		strs := make([]string, len(fields))
		for i, f := range fields {
			strs[i] = f.text
		}
		return rdata.NewTXT(strs...)
	case rrtype.SOA:
		return p.parseSOA(fields)
	case rrtype.SRV:
		return p.parseSRV(fields)
	case rrtype.CAA:
		return p.parseCAA(fields)
	case rrtype.DNAME:
		return p.parseDNAME(fields)
	case rrtype.DS:
		return p.parseDS(fields)
	case rrtype.DNSKEY:
		return p.parseDNSKEY(fields)
	default:
		return nil, fmt.Errorf("type %s not supported in master file parser", t)
	}
}

func (p *parser) parseSRV(fields []fieldTok) (rdata.RData, error) {
	if len(fields) != 4 {
		return nil, fmt.Errorf("SRV: expected 4 fields (priority weight port target), got %d", len(fields))
	}
	pri, err := strconv.ParseUint(fields[0].text, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("SRV priority: %w", err)
	}
	wgt, err := strconv.ParseUint(fields[1].text, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("SRV weight: %w", err)
	}
	port, err := strconv.ParseUint(fields[2].text, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("SRV port: %w", err)
	}
	target, err := p.resolveName(fields[3].text)
	if err != nil {
		return nil, err
	}
	return rdata.NewSRV(uint16(pri), uint16(wgt), uint16(port), target)
}

func (p *parser) parseCAA(fields []fieldTok) (rdata.RData, error) {
	if len(fields) != 3 {
		return nil, fmt.Errorf("CAA: expected 3 fields (flags tag value), got %d", len(fields))
	}
	flags, err := strconv.ParseUint(fields[0].text, 10, 8)
	if err != nil {
		return nil, fmt.Errorf("CAA flags: %w", err)
	}
	tag := fields[1].text
	// CAA value is a quoted character-string; the lexer has already
	// stripped the surrounding quotes (see readQuoted).
	value := fields[2].text
	return rdata.NewCAA(uint8(flags), tag, []byte(value))
}

func (p *parser) parseDNAME(fields []fieldTok) (rdata.RData, error) {
	if len(fields) != 1 {
		return nil, fmt.Errorf("DNAME: expected 1 field (target)")
	}
	target, err := p.resolveName(fields[0].text)
	if err != nil {
		return nil, err
	}
	return rdata.NewDNAME(target)
}

func (p *parser) parseDS(fields []fieldTok) (rdata.RData, error) {
	if len(fields) < 4 {
		return nil, fmt.Errorf("DS: expected ≥4 fields (keytag alg digest-type digest...), got %d", len(fields))
	}
	keytag, err := strconv.ParseUint(fields[0].text, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("DS keytag: %w", err)
	}
	alg, err := strconv.ParseUint(fields[1].text, 10, 8)
	if err != nil {
		return nil, fmt.Errorf("DS algorithm: %w", err)
	}
	dt, err := strconv.ParseUint(fields[2].text, 10, 8)
	if err != nil {
		return nil, fmt.Errorf("DS digest-type: %w", err)
	}
	// Digest is hex; may be split across multiple whitespace-separated
	// fields (RFC 4034 §5.3 master-file form). Concatenate.
	var hexStr strings.Builder
	for _, f := range fields[3:] {
		hexStr.WriteString(f.text)
	}
	digest, err := hexDecode(hexStr.String())
	if err != nil {
		return nil, fmt.Errorf("DS digest: %w", err)
	}
	ds, err := rdata.NewDS(uint16(keytag), rdata.DNSSECAlgorithm(alg), rdata.DSDigestType(dt), digest)
	if err != nil {
		return nil, fmt.Errorf("DS: %w", err)
	}
	return ds, nil
}

func (p *parser) parseDNSKEY(fields []fieldTok) (rdata.RData, error) {
	if len(fields) < 4 {
		return nil, fmt.Errorf("DNSKEY: expected ≥4 fields (flags protocol alg key...), got %d", len(fields))
	}
	flags, err := strconv.ParseUint(fields[0].text, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("DNSKEY flags: %w", err)
	}
	proto, err := strconv.ParseUint(fields[1].text, 10, 8)
	if err != nil {
		return nil, fmt.Errorf("DNSKEY protocol: %w", err)
	}
	alg, err := strconv.ParseUint(fields[2].text, 10, 8)
	if err != nil {
		return nil, fmt.Errorf("DNSKEY algorithm: %w", err)
	}
	// Public key is base64 across remaining fields (RFC 4034 §2.2).
	var b64Str strings.Builder
	for _, f := range fields[3:] {
		b64Str.WriteString(f.text)
	}
	key, err := b64Decode(b64Str.String())
	if err != nil {
		return nil, fmt.Errorf("DNSKEY public key: %w", err)
	}
	dk, err := rdata.NewDNSKEY(uint16(flags), uint8(proto), rdata.DNSSECAlgorithm(alg), key)
	if err != nil {
		return nil, fmt.Errorf("DNSKEY: %w", err)
	}
	return dk, nil
}

func (p *parser) parseSOA(fields []fieldTok) (rdata.SOA, error) {
	var zero rdata.SOA
	if len(fields) != 7 {
		return zero, fmt.Errorf("SOA: expected 7 fields, got %d", len(fields))
	}
	mname, err := p.resolveName(fields[0].text)
	if err != nil {
		return zero, err
	}
	rname, err := p.resolveName(fields[1].text)
	if err != nil {
		return zero, err
	}
	serial, err := strconv.ParseUint(fields[2].text, 10, 32)
	if err != nil {
		return zero, fmt.Errorf("SOA serial: %w", err)
	}
	refresh, err := strconv.ParseInt(fields[3].text, 10, 64)
	if err != nil {
		return zero, fmt.Errorf("SOA refresh: %w", err)
	}
	retry, err := strconv.ParseInt(fields[4].text, 10, 64)
	if err != nil {
		return zero, fmt.Errorf("SOA retry: %w", err)
	}
	expire, err := strconv.ParseInt(fields[5].text, 10, 64)
	if err != nil {
		return zero, fmt.Errorf("SOA expire: %w", err)
	}
	minimum, err := strconv.ParseInt(fields[6].text, 10, 64)
	if err != nil {
		return zero, fmt.Errorf("SOA minimum: %w", err)
	}
	return rdata.NewSOA(mname, rname,
		uint32(serial),
		time.Duration(refresh)*time.Second,
		time.Duration(retry)*time.Second,
		time.Duration(expire)*time.Second,
		time.Duration(minimum)*time.Second,
	)
}
