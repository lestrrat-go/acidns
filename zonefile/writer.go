package zonefile

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
)

// Write emits z as RFC 1035 master-file text. The output begins with
// $ORIGIN and (if a default TTL can be inferred from the SOA minimum)
// a $TTL directive.
func Write(w io.Writer, z Zone) error {
	bw := newBufWriter(w)
	if _, err := fmt.Fprintf(bw, "$ORIGIN %s\n", z.Origin().String()); err != nil {
		return err
	}
	if soa, _, ok := z.SOA(); ok {
		ttl := int64(soa.Minimum().Seconds())
		if ttl > 0 {
			if _, err := fmt.Fprintf(bw, "$TTL %d\n", ttl); err != nil {
				return err
			}
		}
	}
	for _, rec := range z.Records() {
		line := formatRecord(rec, z.Origin())
		if _, err := bw.WriteString(line); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// bufWriter — io.Writer with a Flush() method, fronting any io.Writer.
type bufWriter struct {
	w   io.Writer
	buf []byte
}

func newBufWriter(w io.Writer) *bufWriter { return &bufWriter{w: w} }

func (b *bufWriter) Write(p []byte) (int, error) { b.buf = append(b.buf, p...); return len(p), nil }
func (b *bufWriter) WriteString(s string) (int, error) {
	b.buf = append(b.buf, s...)
	return len(s), nil
}
func (b *bufWriter) Flush() error {
	if len(b.buf) == 0 {
		return nil
	}
	_, err := b.w.Write(b.buf)
	b.buf = b.buf[:0]
	return err
}

func formatRecord(rec wire.Record, origin wire.Name) string {
	owner := relativise(rec.Name(), origin)
	ttl := int64(rec.TTL().Seconds())
	rdataStr := formatRDataPresentation(rec.RData())
	return fmt.Sprintf("%s\t%d\t%s\t%s\t%s\n",
		owner, ttl, rec.Class(), rec.Type(), rdataStr)
}

func relativise(n, origin wire.Name) string {
	if n.Equal(origin) {
		return "@"
	}
	full := n.String()
	o := origin.String()
	if before, ok := strings.CutSuffix(full, "."+o); ok {
		return before
	}
	return full
}

func formatRDataPresentation(rd rdata.RData) string {
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
			parts = append(parts, quoteCharString(s))
		}
		return strings.Join(parts, " ")
	case rdata.SOA:
		return fmt.Sprintf("%s %s (\n\t\t%d\t; serial\n\t\t%d\t; refresh\n\t\t%d\t; retry\n\t\t%d\t; expire\n\t\t%d )\t; minimum",
			v.MName(), v.RName(), v.Serial(),
			int(v.Refresh().Seconds()), int(v.Retry().Seconds()),
			int(v.Expire().Seconds()), int(v.Minimum().Seconds()))
	case rdata.CAA:
		return fmt.Sprintf("%d %s %s", v.Flags(), v.Tag(), quoteCharString(string(v.Value())))
	case rdata.SRV:
		// RFC 2782: priority weight port target
		return fmt.Sprintf("%d %d %d %s", v.Priority(), v.Weight(), v.Port(), v.Target())
	case rdata.DNAME:
		// RFC 6672 §2.1: single target name
		return v.Target().String()
	case rdata.DS:
		// RFC 4034 §5.3: keytag alg digest-type <hex digest>
		return fmt.Sprintf("%d %d %d %s", v.KeyTag(), uint8(v.Algorithm()), uint8(v.DigestType()), hex.EncodeToString(v.Digest()))
	case rdata.DNSKEY:
		// RFC 4034 §2.2: flags protocol algorithm <base64 key>
		return fmt.Sprintf("%d %d %d %s", v.Flags(), v.Protocol(), uint8(v.Algorithm()), base64.StdEncoding.EncodeToString(v.PublicKey()))
	case rdata.Unknown:
		// RFC 3597 generic form: \# <length> <hex>
		b := v.Bytes()
		return fmt.Sprintf("\\# %d %s", len(b), hex.EncodeToString(b))
	default:
		// Fall back to RFC 3597 §5 generic form for any typed rdata we
		// don't have an explicit presentation form for. The writer must
		// never fail on a valid record — round-tripping via the generic
		// form preserves the wire payload exactly.
		b := rdata.Pack(rd)
		return fmt.Sprintf("\\# %d %s", len(b), hex.EncodeToString(b))
	}
}

func quoteCharString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := range len(s) {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20 || c > 0x7e:
			// RFC 1035 §5.1 \DDD: emit bytes outside printable ASCII
			// as three-digit decimal so the file stays text-safe and
			// round-trips through the lexer's \DDD decoder.
			fmt.Fprintf(&b, `\%03d`, c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}
