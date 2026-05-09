package wire_test

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rdata"
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
	"github.com/stretchr/testify/require"
)

// Name wrapper functions in name.go are thin aliases over wirebb but must
// still be exercised via the wire package surface.
func TestNameWrappers(t *testing.T) {
	t.Parallel()

	t.Run("ParseName", func(t *testing.T) {
		t.Parallel()
		n, err := wire.ParseName("example.com")
		require.NoError(t, err)
		require.Equal(t, "example.com.", n.String())
	})

	t.Run("ParseNameInvalid", func(t *testing.T) {
		t.Parallel()
		_, err := wire.ParseName(strings.Repeat("a", 64) + ".example.")
		require.ErrorIs(t, err, wirebb.ErrInvalidName)
	})

	t.Run("MustParseName", func(t *testing.T) {
		t.Parallel()
		n := wire.MustParseName("example.com")
		require.Equal(t, "example.com.", n.String())
	})

	t.Run("RootName", func(t *testing.T) {
		t.Parallel()
		root := wire.RootName()
		require.True(t, root.IsRoot())
	})

	t.Run("NameFromLabels", func(t *testing.T) {
		t.Parallel()
		n, err := wire.NameFromLabels("foo", "bar", "example", "com")
		require.NoError(t, err)
		require.Equal(t, "foo.bar.example.com.", n.String())
	})

	t.Run("NameFromLabelsEmpty", func(t *testing.T) {
		t.Parallel()
		n, err := wire.NameFromLabels()
		require.NoError(t, err)
		require.True(t, n.IsRoot())
	})

	t.Run("NameFromLabelsInvalid", func(t *testing.T) {
		t.Parallel()
		_, err := wire.NameFromLabels("")
		require.ErrorIs(t, err, wirebb.ErrInvalidName)
	})

	t.Run("DecodeName", func(t *testing.T) {
		t.Parallel()
		// Build wire bytes for "example.com" using the packer to
		// produce a normal uncompressed name.
		raw := []byte{
			7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
			3, 'c', 'o', 'm',
			0,
		}
		n, off, err := wire.DecodeName(raw, 0)
		require.NoError(t, err)
		require.Equal(t, len(raw), off)
		require.Equal(t, "example.com.", n.String())
	})

	t.Run("DecodeNameInvalid", func(t *testing.T) {
		t.Parallel()
		// Truncated name.
		_, _, err := wire.DecodeName([]byte{5, 'a', 'b'}, 0)
		require.ErrorIs(t, err, wirebb.ErrInvalidName)
	})
}

// Opcode/RCODE String() default branches and the unknown helper texts.
func TestOpcodeStringFallback(t *testing.T) {
	t.Parallel()

	cases := []struct {
		op   wire.Opcode
		want string
	}{
		{wire.OpcodeQuery, "QUERY"},
		{wire.OpcodeIQuery, "IQUERY"},
		{wire.OpcodeStatus, "STATUS"},
		{wire.OpcodeNotify, "NOTIFY"},
		{wire.OpcodeUpdate, "UPDATE"},
		{wire.OpcodeDSO, "DSO"},
		{wire.Opcode(15), "OPCODE15"},
		{wire.Opcode(7), "OPCODE7"},
	}
	for _, c := range cases {
		require.Equal(t, c.want, c.op.String())
	}
}

func TestRCODEStringFallback(t *testing.T) {
	t.Parallel()

	cases := []struct {
		rc   wire.RCODE
		want string
	}{
		{wire.RCODENoError, "NOERROR"},
		{wire.RCODEFormErr, "FORMERR"},
		{wire.RCODEServFail, "SERVFAIL"},
		{wire.RCODENXDomain, "NXDOMAIN"},
		{wire.RCODENotImp, "NOTIMP"},
		{wire.RCODERefused, "REFUSED"},
		{wire.RCODEYXDomain, "YXDOMAIN"},
		{wire.RCODEYXRRSet, "YXRRSET"},
		{wire.RCODENXRRSet, "NXRRSET"},
		{wire.RCODENotAuth, "NOTAUTH"},
		{wire.RCODENotZone, "NOTZONE"},
		{wire.RCODE(11), "RCODE11"},
		{wire.RCODE(15), "RCODE15"},
	}
	for _, c := range cases {
		require.Equal(t, c.want, c.rc.String())
	}
}

// Flags With* setters with the false branch of setBit.
func TestFlagsClearBits(t *testing.T) {
	t.Parallel()

	all := wire.Flags(0).
		WithResponse(true).
		WithAuthoritative(true).
		WithTruncated(true).
		WithRecursionDesired(true).
		WithRecursionAvailable(true).
		WithAuthenticData(true).
		WithCheckingDisabled(true)
	require.True(t, all.Response())

	cleared := all.
		WithResponse(false).
		WithAuthoritative(false).
		WithTruncated(false).
		WithRecursionDesired(false).
		WithRecursionAvailable(false).
		WithAuthenticData(false).
		WithCheckingDisabled(false)
	require.False(t, cleared.Response())
	require.False(t, cleared.Authoritative())
	require.False(t, cleared.Truncated())
	require.False(t, cleared.RecursionDesired())
	require.False(t, cleared.RecursionAvailable())
	require.False(t, cleared.AuthenticData())
	require.False(t, cleared.CheckingDisabled())
}

// EDNS option mismatched-code accessors.
func TestEDNSOptionAccessorsMismatch(t *testing.T) {
	t.Parallel()

	other, err := wire.NewEDNSOption(0xfff0, []byte{1, 2, 3})
	require.NoError(t, err)

	t.Run("NSIDIdentifier", func(t *testing.T) {
		t.Parallel()
		_, ok := wire.NSIDIdentifier(other)
		require.False(t, ok)
	})

	t.Run("EDNSExpireSecondsWrongCode", func(t *testing.T) {
		t.Parallel()
		_, ok := wire.EDNSExpireSeconds(other)
		require.False(t, ok)
	})

	t.Run("TCPKeepaliveTimeoutWrongCode", func(t *testing.T) {
		t.Parallel()
		_, ok := wire.TCPKeepaliveTimeout(other)
		require.False(t, ok)
	})

	t.Run("TCPKeepaliveTimeoutWrongLength", func(t *testing.T) {
		t.Parallel()
		// Empty-payload keepalive (query-side) returns false.
		empty := wire.NewTCPKeepalive(0)
		_, ok := wire.TCPKeepaliveTimeout(empty)
		require.False(t, ok)
	})

	t.Run("ClientSubnetWrongCode", func(t *testing.T) {
		t.Parallel()
		_, _, ok := wire.ClientSubnet(other)
		require.False(t, ok)
	})

	t.Run("ClientSubnetTooShort", func(t *testing.T) {
		t.Parallel()
		short, err := wire.NewEDNSOption(8, []byte{0, 1}) // ECS code, but <4 bytes
		require.NoError(t, err)
		_, _, ok := wire.ClientSubnet(short)
		require.False(t, ok)
	})

	t.Run("ClientSubnetUnknownFamily", func(t *testing.T) {
		t.Parallel()
		// Family=99 (unknown).
		bad, err := wire.NewEDNSOption(8, []byte{0x00, 0x63, 0x00, 0x00})
		require.NoError(t, err)
		_, _, ok := wire.ClientSubnet(bad)
		require.False(t, ok)
	})

	t.Run("CookiesWrongCode", func(t *testing.T) {
		t.Parallel()
		_, _, ok := wire.Cookies(other)
		require.False(t, ok)
	})

	t.Run("CookiesBadLength", func(t *testing.T) {
		t.Parallel()
		// 9 bytes - between 8 and 16, malformed.
		bad, err := wire.NewEDNSOption(10, make([]byte, 9))
		require.NoError(t, err)
		_, _, ok := wire.Cookies(bad)
		require.False(t, ok)
	})

	t.Run("CookiesOversize", func(t *testing.T) {
		t.Parallel()
		bad, err := wire.NewEDNSOption(10, make([]byte, 41))
		require.NoError(t, err)
		_, _, ok := wire.Cookies(bad)
		require.False(t, ok)
	})

	t.Run("ExtendedErrorWrongCode", func(t *testing.T) {
		t.Parallel()
		_, _, ok := wire.ExtendedError(other)
		require.False(t, ok)
	})

	t.Run("ExtendedErrorTooShort", func(t *testing.T) {
		t.Parallel()
		bad, err := wire.NewEDNSOption(15, []byte{0x00})
		require.NoError(t, err)
		_, _, ok := wire.ExtendedError(bad)
		require.False(t, ok)
	})

	t.Run("ZoneVersionWrongCode", func(t *testing.T) {
		t.Parallel()
		_, _, ok := wire.ZoneVersionSOASerial(other)
		require.False(t, ok)
	})

	t.Run("ZoneVersionWrongType", func(t *testing.T) {
		t.Parallel()
		// Code 19 (zone version), 6 bytes, type byte != 0.
		bad, err := wire.NewEDNSOption(19, []byte{0x02, 0x09, 0x00, 0x00, 0x00, 0x00})
		require.NoError(t, err)
		_, _, ok := wire.ZoneVersionSOASerial(bad)
		require.False(t, ok)
	})
}

// NewClientSubnet error paths.
func TestNewClientSubnetErrors(t *testing.T) {
	t.Parallel()

	t.Run("InvalidPrefix", func(t *testing.T) {
		t.Parallel()
		_, err := wire.NewClientSubnet(netip.Prefix{}, 0)
		require.ErrorIs(t, err, wire.ErrInvalidMessage)
	})

	t.Run("SourceTooLong", func(t *testing.T) {
		t.Parallel()
		// /33 on a v4 address — exceeds 32-bit width.
		bad := netip.PrefixFrom(netip.MustParseAddr("192.0.2.0"), 33)
		_, err := wire.NewClientSubnet(bad, 0)
		require.ErrorIs(t, err, wire.ErrInvalidMessage)
	})
}

// NewClientServerCookie length-error paths.
func TestNewClientServerCookieErrors(t *testing.T) {
	t.Parallel()

	cc := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}

	_, err := wire.NewClientServerCookie(cc, []byte{1, 2, 3})
	require.ErrorIs(t, err, wire.ErrInvalidCookie)

	// >32 bytes server cookie also rejected.
	_, err = wire.NewClientServerCookie(cc, make([]byte, 33))
	require.ErrorIs(t, err, wire.ErrInvalidCookie)
}

// NewEDNSOption oversize data error.
func TestNewEDNSOptionOversize(t *testing.T) {
	t.Parallel()

	_, err := wire.NewEDNSOption(99, make([]byte, 0x10000))
	require.ErrorIs(t, err, wire.ErrInvalidMessage)
}

// NewAlgorithmUnderstood rejects non-DAU/DHU/N3U codes.
func TestNewAlgorithmUnderstoodInvalidCode(t *testing.T) {
	t.Parallel()

	_, err := wire.NewAlgorithmUnderstood(99)
	require.ErrorIs(t, err, wire.ErrInvalidMessage)
}

func TestNewAlgorithmUnderstoodHappyCases(t *testing.T) {
	t.Parallel()

	for _, code := range []uint16{wire.EDNSOptionDAU, wire.EDNSOptionDHU, wire.EDNSOptionN3U} {
		opt, err := wire.NewAlgorithmUnderstood(code, 8, 13)
		require.NoError(t, err)
		require.Equal(t, code, opt.Code())
		require.Equal(t, []byte{8, 13}, opt.Data())
	}
}

// Cookies: empty server-cookie path (8-byte payload) — exercises the
// `len(d) > 8` false branch.
func TestCookiesClientOnly(t *testing.T) {
	t.Parallel()

	cc := [8]byte{9, 8, 7, 6, 5, 4, 3, 2}
	o := wire.NewClientCookie(cc)
	gotC, gotS, ok := wire.Cookies(o)
	require.True(t, ok)
	require.Equal(t, cc, gotC)
	require.Empty(t, gotS)
}

// ReportChannel mismatched code.
func TestReportChannelAgentMismatch(t *testing.T) {
	t.Parallel()

	other, err := wire.NewEDNSOption(99, []byte{0})
	require.NoError(t, err)
	_, ok := wire.ReportChannelAgent(other)
	require.False(t, ok)
}

// ReportChannelAgent with garbage data fails to decode the embedded name.
func TestReportChannelAgentMalformed(t *testing.T) {
	t.Parallel()

	// Code 18 (Report-Channel) with truncated label data.
	bad, err := wire.NewEDNSOption(18, []byte{0x05, 'a'})
	require.NoError(t, err)
	_, ok := wire.ReportChannelAgent(bad)
	require.False(t, ok)
}

// BuildErrorReportName: invalid agent.
func TestBuildErrorReportNameInvalidAgent(t *testing.T) {
	t.Parallel()

	_, err := wire.BuildErrorReportName(
		wirebb.MustParse("broken.example.com"),
		rrtype.A,
		wire.ExtendedErrorOther,
		wirebb.Name{}, // zero name → not valid
	)
	require.ErrorIs(t, err, wire.ErrInvalidMessage)
}

// LLQ + UpdateLease constructors smoke tests.
func TestLLQAndUpdateLease(t *testing.T) {
	t.Parallel()

	llq := wire.NewLLQ(wire.LLQOpcodeSetup, wire.LLQErrNoError, 0xdeadbeef, 7200)
	require.Equal(t, wire.EDNSOptionLLQ, llq.Code())
	require.Len(t, llq.Data(), 18)

	ul := wire.NewUpdateLease(7200)
	require.Equal(t, wire.EDNSOptionUL, ul.Code())
	require.Len(t, ul.Data(), 4)
}

// RDataAs failure branches.
func TestRDataAsMismatch(t *testing.T) {
	t.Parallel()

	rec := wire.NewRecord(
		wirebb.MustParse("example.com"),
		60*time.Second,
		rdata.MustNewA(netip.MustParseAddr("192.0.2.1")),
	)

	// Asking for AAAA on an A record returns false.
	_, ok := wire.RDataAs[rdata.AAAA](rec)
	require.False(t, ok)

	a, ok := wire.RDataAs[rdata.A](rec)
	require.True(t, ok)
	require.Equal(t, "192.0.2.1", a.Addr().String())
}

// Unmarshal: corrupt additional that *peeks* a valid name+type but fails
// the full record unpack (e.g. truncated rdata after the type).
func TestUnmarshalTruncatedAdditionalAfterPeek(t *testing.T) {
	t.Parallel()

	// Header arcount=1, then a name "x." + type=A + class=IN + ttl + rdlen=4
	// but only 2 rdata bytes.
	buf := []byte{
		0, 1, // ID
		0, 0, // flags
		0, 0, // qd
		0, 0, // an
		0, 0, // ns
		0, 1, // ar
		// record:
		1, 'x', 0, // name "x."
		0, 1, // type=A
		0, 1, // class=IN
		0, 0, 0, 60, // ttl
		0, 4, // rdlen
		192, 0, // truncated rdata
	}
	_, err := wire.Unmarshal(buf)
	require.ErrorIs(t, err, wire.ErrInvalidMessage)
}

// Unmarshal: two OPT pseudo-RRs is rejected.
func TestUnmarshalDoubleOPTRejected(t *testing.T) {
	t.Parallel()

	e := mustEDNS(t, wire.NewEDNSBuilder().UDPSize(1232))
	q := wire.NewQuestion(wirebb.MustParse("example.com"), rrtype.A)
	m, err := wire.NewMessageBuilder().ID(1).Question(q).EDNS(e).Build()
	require.NoError(t, err)

	buf, err := wire.Marshal(m)
	require.NoError(t, err)

	// Forge a second OPT by appending another packed OPT and bumping arcount.
	m2, err := wire.NewMessageBuilder().ID(1).Question(q).EDNS(e).Build()
	require.NoError(t, err)
	buf2, err := wire.Marshal(m2)
	require.NoError(t, err)

	// The OPT wire bytes are everything after the header+question portion.
	// Rebuild: take buf as-is, append the OPT part of buf2, bump arcount.
	hdr := buf[:12]
	q1Len := len(buf) - 12 - findOPTLen(buf)
	question := buf[12 : 12+q1Len]
	opt1 := buf[12+q1Len:]
	opt2 := buf2[12+q1Len:]

	combined := make([]byte, 0, len(hdr)+len(question)+len(opt1)+len(opt2))
	combined = append(combined, hdr...)
	combined = append(combined, question...)
	combined = append(combined, opt1...)
	combined = append(combined, opt2...)
	// Bump arcount from 1 to 2.
	combined[10] = 0
	combined[11] = 2

	_, err = wire.Unmarshal(combined)
	require.ErrorIs(t, err, wire.ErrInvalidMessage)
}

// findOPTLen finds the length of the trailing OPT pseudo-RR in a serialised
// query that contains exactly one question and one OPT in additionals.
// OPT wire layout: NAME(1) + TYPE(2) + CLASS(2) + TTL(4) + RDLEN(2) + RDATA.
func findOPTLen(_ []byte) int {
	// Walk backward: last record is OPT. The OPT NAME is always the root
	// (single 0x00 byte), so the OPT is exactly 11 + rdlen bytes.
	// rdlen is the two bytes 9 from the end of the record (i.e. positions
	// len-rdlen-2..len-rdlen-1 from the start of the rdata).
	// Easier: walk through "name=root, type=2 bytes, class=2, ttl=4, rdlen=2, rdata=rdlen".
	// Total = 1 + 2 + 2 + 4 + 2 + rdlen = 11 + rdlen.
	// We don't know rdlen without parsing — but for our specific Build above
	// (no options set), rdlen = 0, so the OPT is exactly 11 bytes.
	return 11
}

// Marshal: rdata too large for type — synthesised via a large TXT.
func TestMarshalRDataTooLarge(t *testing.T) {
	t.Parallel()

	// TXT with many short strings: total wire size 65536+ bytes.
	// Each TXT string segment is <length><bytes>, max segment 255 bytes.
	// 257 bytes per segment, need ~256 segments to overflow 65535.
	segments := make([]string, 257)
	for i := range segments {
		segments[i] = strings.Repeat("a", 255)
	}
	txt, err := rdata.NewTXT(segments...)
	require.NoError(t, err)

	rec := wire.NewRecord(wirebb.MustParse("example.com"), 60*time.Second, txt)
	m, err := wire.NewMessageBuilder().Answer(rec).Build()
	require.NoError(t, err)

	_, err = wire.Marshal(m)
	require.ErrorIs(t, err, wire.ErrInvalidMessage)
}

// NewRRsetFromRDatas error paths.
func TestNewRRsetFromRDatasErrors(t *testing.T) {
	t.Parallel()

	t.Run("Empty", func(t *testing.T) {
		t.Parallel()
		_, err := wire.NewRRsetFromRDatas(wirebb.MustParse("x."), rrtype.ClassIN, time.Minute)
		require.ErrorIs(t, err, wire.ErrInvalidMessage)
	})

	t.Run("Mismatch", func(t *testing.T) {
		t.Parallel()
		_, err := wire.NewRRsetFromRDatas(
			wirebb.MustParse("x."),
			rrtype.ClassIN,
			time.Minute,
			rdata.MustNewA(netip.MustParseAddr("192.0.2.1")),
			rdata.MustNewAAAA(netip.MustParseAddr("2001:db8::1")),
		)
		require.ErrorIs(t, err, wire.ErrInvalidMessage)
	})
}

// Unmarshal: truncated authority.
func TestUnmarshalTruncatedAuthority(t *testing.T) {
	t.Parallel()
	hdr := []byte{
		0, 1,
		0, 0,
		0, 0,
		0, 0,
		0, 1, // nscount=1
		0, 0,
	}
	_, err := wire.Unmarshal(hdr)
	require.ErrorIs(t, err, wire.ErrInvalidMessage)
}

// Unmarshal: additional whose name parses but type peek hits truncation.
func TestUnmarshalAdditionalNameOnly(t *testing.T) {
	t.Parallel()

	// Header arcount=1, then just a 0-byte name (root) but no type/class/etc.
	buf := []byte{
		0, 1,
		0, 0,
		0, 0,
		0, 0,
		0, 0,
		0, 1, // arcount=1
		0, // root name only
	}
	_, err := wire.Unmarshal(buf)
	require.ErrorIs(t, err, wire.ErrInvalidMessage)
}

// Marshal: rdata oversize in Authority section.
func TestMarshalAuthorityOversize(t *testing.T) {
	t.Parallel()

	segments := make([]string, 257)
	for i := range segments {
		segments[i] = strings.Repeat("a", 255)
	}
	txt, err := rdata.NewTXT(segments...)
	require.NoError(t, err)

	rec := wire.NewRecord(wirebb.MustParse("example.com"), 60*time.Second, txt)
	m, err := wire.NewMessageBuilder().Authority(rec).Build()
	require.NoError(t, err)

	_, err = wire.Marshal(m)
	require.ErrorIs(t, err, wire.ErrInvalidMessage)
}

// Marshal: rdata oversize in Additional section.
func TestMarshalAdditionalOversize(t *testing.T) {
	t.Parallel()

	segments := make([]string, 257)
	for i := range segments {
		segments[i] = strings.Repeat("a", 255)
	}
	txt, err := rdata.NewTXT(segments...)
	require.NoError(t, err)

	rec := wire.NewRecord(wirebb.MustParse("example.com"), 60*time.Second, txt)
	m, err := wire.NewMessageBuilder().Additional(rec).Build()
	require.NoError(t, err)

	_, err = wire.Marshal(m)
	require.ErrorIs(t, err, wire.ErrInvalidMessage)
}

// Unmarshal: OPT pseudo-RR with truncated rdata (rdlen exceeds remaining).
func TestUnmarshalOPTTruncatedRDLen(t *testing.T) {
	t.Parallel()

	// arcount=1, name=root, type=OPT(41), class=1232, ttl=0, rdlen=10 but
	// no rdata bytes follow.
	buf := []byte{
		0, 1,
		0, 0,
		0, 0,
		0, 0,
		0, 0,
		0, 1, // arcount=1
		0,     // root name
		0, 41, // type=OPT
		0x04, 0xd0, // udp size 1232
		0, 0, 0, 0, // ttl
		0, 10, // rdlen=10, no follow
	}
	_, err := wire.Unmarshal(buf)
	require.ErrorIs(t, err, wire.ErrInvalidMessage)
}

// Unmarshal: OPT pseudo-RR with malformed inner option (data length exceeds
// remaining rdata).
func TestUnmarshalOPTMalformedOption(t *testing.T) {
	t.Parallel()

	// rdlen=4, but the option claims length=99 with no body.
	// rdata layout: code(2) + len(2) + body(len)
	buf := []byte{
		0, 1,
		0, 0,
		0, 0,
		0, 0,
		0, 0,
		0, 1, // arcount=1
		0,     // root name
		0, 41, // type=OPT
		0x04, 0xd0, // udp size 1232
		0, 0, 0, 0, // ttl
		0, 4, // rdlen=4 — exactly covers code(2)+len(2)
		0, 99, 0, 99, // option code 99, declared len 99 but rdata stops here
	}
	_, err := wire.Unmarshal(buf)
	require.ErrorIs(t, err, wire.ErrInvalidMessage)
}

// Builder Build error path: forces err via deliberate misconfiguration. The
// current Builder never assigns b.err itself; verify the happy path returns
// nil err and Build returns a non-nil Message — this is the path that *was*
// at 66.7% because no `b.err != nil` case existed.
func TestBuilderBuildSucceedsWithoutErr(t *testing.T) {
	t.Parallel()

	m, err := wire.NewMessageBuilder().Build()
	require.NoError(t, err)
	require.NotNil(t, m)
	require.Equal(t, uint16(0), m.ID())
}

// joinLabels empty: only reachable if BuildErrorReportName ever produces an
// empty parts slice. It never does in practice, but cover the function via a
// boundary qname (single-label).
func TestBuildErrorReportSingleLabel(t *testing.T) {
	t.Parallel()

	n, err := wire.BuildErrorReportName(
		wirebb.MustParse("example."),
		rrtype.A,
		wire.ExtendedErrorOther,
		wirebb.MustParse("agent."),
	)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(n.String(), "_er.1.example.0._er.agent."))
}

// Unmarshal: additional whose name fails to parse.
func TestUnmarshalAdditionalBadName(t *testing.T) {
	t.Parallel()

	// arcount=1; first byte after header is 0xc0 0x00 — pointer to header,
	// which is reserved/invalid.
	buf := []byte{
		0, 1,
		0, 0,
		0, 0,
		0, 0,
		0, 0,
		0, 1, // arcount=1
		0xff, // illegal label-length top bits 11 with a non-pointer follow
	}
	_, err := wire.Unmarshal(buf)
	require.ErrorIs(t, err, wire.ErrInvalidMessage)
}
