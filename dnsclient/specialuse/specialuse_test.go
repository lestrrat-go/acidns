package specialuse_test

import (
	"testing"

	"github.com/lestrrat-go/acidns/dnsclient/specialuse"
	"github.com/lestrrat-go/acidns/dnsname"
	"github.com/stretchr/testify/require"
)

func TestFor(t *testing.T) {
	t.Parallel()
	cases := map[string]specialuse.Disposition{
		"example.com":     specialuse.Pass, // RFC 6761 §6.5 — apps SHOULD NOT special-case
		"www.example.com": specialuse.Pass,
		"foo.example":     specialuse.Pass,
		"a.b.test":        specialuse.Refuse,
		"any.invalid":     specialuse.Refuse,
		"foo.onion":       specialuse.Refuse,
		"local":           specialuse.Local,
		"_dns._udp.local": specialuse.Local,
		"localhost":       specialuse.SynthLocalhost,
		"db.localhost":    specialuse.SynthLocalhost,
		"acidns.dev":      specialuse.Pass,
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			n := dnsname.MustParse(name)
			require.Equal(t, want, specialuse.For(n))
		})
	}
}
