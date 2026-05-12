package zonefile

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// DefaultGenerateMaxIterations caps how many records a single $GENERATE
// directive may produce. Tunable via [WithGenerateMaxIterations]. The
// cap prevents a single line from exhausting memory; sized to fit a
// full IPv4 /16 fan-out (2^16 = 65_536 records) exactly. Operators
// needing a larger expansion can opt into a higher ceiling explicitly.
const DefaultGenerateMaxIterations = 1 << 16 // 65_536

// handleGenerate parses and expands a $GENERATE directive. BIND 9 grammar:
//
//	$GENERATE <range> <lhs> [<ttl>] [<class>] <type> <rhs>
//
// where <range> is "start-stop" or "start-stop/step" and <lhs>/<rhs>
// may contain substitution sequences:
//
//	$                     — current iteration value, decimal
//	\$                    — literal '$'
//	${offset}             — value+offset, decimal
//	${offset,width}       — value+offset, decimal, zero-padded
//	${offset,width,fmt}   — value+offset, formatted; fmt is one of
//	                        d (decimal), o (octal), x (hex lower),
//	                        X (hex upper)
//
// BIND's nibble formats (n / N) are intentionally not implemented in
// this first version: they only matter for IPv6 reverse-zone fan-out
// and have inconsistent semantics across implementations. Add when a
// concrete caller needs them.
func (p *parser) handleGenerate(fields []fieldTok) error {
	line := fields[0].line
	if len(fields) < 5 {
		return p.lineErr(line, "$GENERATE: expected at least 4 arguments, got %d", len(fields)-1)
	}
	rng, err := parseGenerateRange(fields[1].text)
	if err != nil {
		return p.lineErr(line, "$GENERATE range: %w", err)
	}
	iter := rng.iterations()
	if iter > p.maxGenerateIterations {
		return p.lineErr(line, "$GENERATE: %d iterations exceeds cap %d (see WithGenerateMaxIterations)", iter, p.maxGenerateIterations)
	}

	lhsTmpl := fields[2].text
	rest := fields[3:]

	ttl := p.defaultTTL
	class := rrtype.ClassIN
	for len(rest) > 0 {
		tok := rest[0].text
		if class != rrtype.ClassIN {
			break
		}
		if t, perr := strconv.ParseInt(tok, 10, 64); perr == nil {
			if t < 0 || t > maxTTL {
				return p.lineErr(rest[0].line, "$GENERATE TTL %d out of range (RFC 2308 §8: 0..%d)", t, maxTTL)
			}
			ttl = t
			rest = rest[1:]
			continue
		}
		if c, ok := parseClass(tok); ok {
			class = c
			rest = rest[1:]
			continue
		}
		break
	}
	if len(rest) == 0 {
		return p.lineErr(line, "$GENERATE: missing RR type")
	}
	t, ok := rrtype.Parse(rest[0].text)
	if !ok {
		return p.lineErr(rest[0].line, "$GENERATE: unknown RR type %q", rest[0].text)
	}
	rhsTokens := rest[1:]
	if ttl < 0 {
		return p.lineErr(line, "$GENERATE: TTL not set (use $TTL or supply explicit TTL)")
	}

	subBuf := make([]fieldTok, len(rhsTokens))
	for v := rng.start; ; v += rng.step {
		ownerStr, err := substituteGenerate(lhsTmpl, v)
		if err != nil {
			return p.lineErr(line, "$GENERATE lhs: %w", err)
		}
		owner, err := p.resolveName(ownerStr)
		if err != nil {
			return p.lineErr(line, "$GENERATE: %w", err)
		}
		for i, tok := range rhsTokens {
			subbed, err := substituteGenerate(tok.text, v)
			if err != nil {
				return p.lineErr(line, "$GENERATE rhs: %w", err)
			}
			subBuf[i] = fieldTok{text: subbed, quoted: tok.quoted, line: tok.line}
		}
		rd, err := p.parseRData(t, subBuf)
		if err != nil {
			return p.lineErr(line, "$GENERATE rdata (value=%d): %w", v, err)
		}
		rec := wire.NewRecordClass(owner, class, time.Duration(ttl)*time.Second, rd)
		p.records = append(p.records, rec)
		p.prevName = owner

		if v == rng.stop {
			break
		}
		// Overflow guard: rng.iterations() already bounded this to
		// maxGenerateIterations, so v+step cannot exceed stop+step
		// here, but a final == without step alignment would loop.
		if v+rng.step > rng.stop {
			break
		}
	}
	return nil
}

type generateRange struct {
	start, stop, step int
}

func (g generateRange) iterations() int {
	return (g.stop-g.start)/g.step + 1
}

func parseGenerateRange(s string) (generateRange, error) {
	stepStr := ""
	if i := strings.IndexByte(s, '/'); i >= 0 {
		stepStr = s[i+1:]
		s = s[:i]
	}
	dash := strings.IndexByte(s, '-')
	if dash <= 0 || dash == len(s)-1 {
		return generateRange{}, fmt.Errorf("expected start-stop, got %q", s)
	}
	start, err := strconv.Atoi(s[:dash])
	if err != nil {
		return generateRange{}, fmt.Errorf("start: %w", err)
	}
	stop, err := strconv.Atoi(s[dash+1:])
	if err != nil {
		return generateRange{}, fmt.Errorf("stop: %w", err)
	}
	if start < 0 || stop < 0 {
		return generateRange{}, fmt.Errorf("negative bound (start=%d, stop=%d)", start, stop)
	}
	if stop < start {
		return generateRange{}, fmt.Errorf("stop %d less than start %d", stop, start)
	}
	step := 1
	if stepStr != "" {
		step, err = strconv.Atoi(stepStr)
		if err != nil {
			return generateRange{}, fmt.Errorf("step: %w", err)
		}
		if step <= 0 {
			return generateRange{}, fmt.Errorf("step %d must be positive", step)
		}
	}
	return generateRange{start: start, stop: stop, step: step}, nil
}

// substituteGenerate applies $-substitution to template, returning the
// expanded string. value is the current iteration value.
func substituteGenerate(template string, value int) (string, error) {
	var sb strings.Builder
	sb.Grow(len(template) + 8)
	for i := 0; i < len(template); i++ {
		c := template[i]
		if c == '\\' && i+1 < len(template) && template[i+1] == '$' {
			sb.WriteByte('$')
			i++
			continue
		}
		if c != '$' {
			sb.WriteByte(c)
			continue
		}
		// bare $ or ${spec}
		if i+1 < len(template) && template[i+1] == '{' {
			end := strings.IndexByte(template[i+2:], '}')
			if end < 0 {
				return "", fmt.Errorf("unterminated ${ at offset %d", i)
			}
			spec := template[i+2 : i+2+end]
			formatted, err := formatGenerateSubst(spec, value)
			if err != nil {
				return "", fmt.Errorf("${%s}: %w", spec, err)
			}
			sb.WriteString(formatted)
			i += 2 + end // skip through closing }
			continue
		}
		// bare $: decimal, no padding
		sb.WriteString(strconv.Itoa(value))
	}
	return sb.String(), nil
}

// formatGenerateSubst parses a ${...} substitution spec (the bytes
// between the braces) and renders it. Spec grammar:
//
//	offset[,width[,format]]
//
// All three fields are optional after each other; the parser allows a
// bare ${} (treated as ${0,0,d}) for symmetry though no real zone file
// uses that form.
func formatGenerateSubst(spec string, value int) (string, error) {
	offset := 0
	width := 0
	format := byte('d')

	parts := strings.SplitN(spec, ",", 3)
	if len(parts) >= 1 && parts[0] != "" {
		v, err := strconv.Atoi(parts[0])
		if err != nil {
			return "", fmt.Errorf("offset: %w", err)
		}
		offset = v
	}
	if len(parts) >= 2 && parts[1] != "" {
		w, err := strconv.Atoi(parts[1])
		if err != nil {
			return "", fmt.Errorf("width: %w", err)
		}
		if w < 0 {
			return "", fmt.Errorf("width %d must be non-negative", w)
		}
		width = w
	}
	if len(parts) >= 3 && parts[2] != "" {
		if len(parts[2]) != 1 {
			return "", fmt.Errorf("format %q must be a single character", parts[2])
		}
		format = parts[2][0]
	}

	n := value + offset
	var rendered string
	switch format {
	case 'd':
		rendered = strconv.FormatInt(int64(n), 10)
	case 'o':
		rendered = strconv.FormatInt(int64(n), 8)
	case 'x':
		rendered = strconv.FormatInt(int64(n), 16)
	case 'X':
		rendered = strings.ToUpper(strconv.FormatInt(int64(n), 16))
	default:
		return "", fmt.Errorf("unsupported format %q (want d, o, x, or X)", format)
	}

	if width > 0 && len(rendered) < width {
		pad := strings.Repeat("0", width-len(rendered))
		// Preserve a leading '-' on negative values: pad after the sign.
		if strings.HasPrefix(rendered, "-") {
			rendered = "-" + pad + rendered[1:]
		} else {
			rendered = pad + rendered
		}
	}
	return rendered, nil
}
