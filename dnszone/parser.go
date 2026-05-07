package dnszone

import (
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
	if leadingWS {
		// blank owner: re-use previous name
		if !p.prevName.IsValid() {
			return fmt.Errorf("line %d: blank owner with no preceding RR", fields[0].line)
		}
	} else {
		ownerTok = &fields[0]
		fields = fields[1:]
	}

	owner, err := p.resolveName(ownerOrPrev(ownerTok, p.prevName))
	if err != nil {
		return fmt.Errorf("line %d: %w", fields[0].line, err)
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
		return fmt.Errorf("line %d: missing RR type", fields[0].line)
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

func ownerOrPrev(tok *fieldTok, prev wire.Name) string {
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
			return nil, fmt.Errorf("A: expected 1 field, got %d", len(fields))
		}
		ip, err := netip.ParseAddr(fields[0].text)
		if err != nil {
			return nil, fmt.Errorf("A: %w", err)
		}
		if !ip.Is4() {
			return nil, fmt.Errorf("A: not an IPv4 address: %s", fields[0].text)
		}
		return rdata.NewA(ip), nil
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
		return rdata.NewAAAA(ip), nil
	case rrtype.NS:
		if len(fields) != 1 {
			return nil, fmt.Errorf("NS: expected 1 field")
		}
		n, err := p.resolveName(fields[0].text)
		if err != nil {
			return nil, err
		}
		return rdata.NewNS(n), nil
	case rrtype.CNAME:
		if len(fields) != 1 {
			return nil, fmt.Errorf("CNAME: expected 1 field")
		}
		n, err := p.resolveName(fields[0].text)
		if err != nil {
			return nil, err
		}
		return rdata.NewCNAME(n), nil
	case rrtype.PTR:
		if len(fields) != 1 {
			return nil, fmt.Errorf("PTR: expected 1 field")
		}
		n, err := p.resolveName(fields[0].text)
		if err != nil {
			return nil, err
		}
		return rdata.NewPTR(n), nil
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
		return rdata.NewMX(uint16(pref), n), nil
	case rrtype.TXT:
		strs := make([]string, len(fields))
		for i, f := range fields {
			strs[i] = f.text
		}
		return rdata.NewTXT(strs...)
	case rrtype.SOA:
		return p.parseSOA(fields)
	default:
		return nil, fmt.Errorf("type %s not supported in master file parser", t)
	}
}

func (p *parser) parseSOA(fields []fieldTok) (rdata.SOA, error) {
	if len(fields) != 7 {
		return nil, fmt.Errorf("SOA: expected 7 fields, got %d", len(fields))
	}
	mname, err := p.resolveName(fields[0].text)
	if err != nil {
		return nil, err
	}
	rname, err := p.resolveName(fields[1].text)
	if err != nil {
		return nil, err
	}
	serial, err := strconv.ParseUint(fields[2].text, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("SOA serial: %w", err)
	}
	refresh, err := strconv.ParseInt(fields[3].text, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("SOA refresh: %w", err)
	}
	retry, err := strconv.ParseInt(fields[4].text, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("SOA retry: %w", err)
	}
	expire, err := strconv.ParseInt(fields[5].text, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("SOA expire: %w", err)
	}
	minimum, err := strconv.ParseInt(fields[6].text, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("SOA minimum: %w", err)
	}
	return rdata.NewSOA(mname, rname,
		uint32(serial),
		time.Duration(refresh)*time.Second,
		time.Duration(retry)*time.Second,
		time.Duration(expire)*time.Second,
		time.Duration(minimum)*time.Second,
	), nil
}
