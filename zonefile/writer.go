package zonefile

import (
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
		line, err := formatRecord(rec, z.Origin())
		if err != nil {
			return err
		}
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

func formatRecord(rec wire.Record, origin wire.Name) (string, error) {
	owner := relativise(rec.Name(), origin)
	ttl := int64(rec.TTL().Seconds())
	rdataStr, err := formatRDataPresentation(rec.RData(), origin)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s\t%d\t%s\t%s\t%s\n",
		owner, ttl, rec.Class(), rec.Type(), rdataStr), nil
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

func formatRDataPresentation(rd rdata.RData, _ wire.Name) (string, error) {
	switch v := rd.(type) {
	case rdata.A:
		return v.Addr().String(), nil
	case rdata.AAAA:
		return v.Addr().String(), nil
	case rdata.CNAME:
		return v.Target().String(), nil
	case rdata.NS:
		return v.NSDName().String(), nil
	case rdata.PTR:
		return v.PtrDName().String(), nil
	case rdata.MX:
		return fmt.Sprintf("%d %s", v.Preference(), v.Exchange()), nil
	case rdata.TXT:
		var parts []string
		for _, s := range v.Strings() {
			parts = append(parts, quoteCharString(s))
		}
		return strings.Join(parts, " "), nil
	case rdata.SOA:
		return fmt.Sprintf("%s %s (\n\t\t%d\t; serial\n\t\t%d\t; refresh\n\t\t%d\t; retry\n\t\t%d\t; expire\n\t\t%d )\t; minimum",
			v.MName(), v.RName(), v.Serial(),
			int(v.Refresh().Seconds()), int(v.Retry().Seconds()),
			int(v.Expire().Seconds()), int(v.Minimum().Seconds())), nil
	case rdata.CAA:
		return fmt.Sprintf("%d %s %s", v.Flags(), v.Tag(), quoteCharString(string(v.Value()))), nil
	case rdata.Unknown:
		// RFC 3597 generic form: \# <length> <hex>
		b := v.Bytes()
		return fmt.Sprintf("\\# %d %s", len(b), hex.EncodeToString(b)), nil
	default:
		return "", fmt.Errorf("zonefile: cannot present rdata of type %s", rd.Type())
	}
}

func quoteCharString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := range len(s) {
		c := s[i]
		switch c {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}
