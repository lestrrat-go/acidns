package webui

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/doh"
	"github.com/lestrrat-go/acidns/dot"
	"github.com/lestrrat-go/acidns/wire"
	"github.com/lestrrat-go/acidns/wire/rrtype"
)

// queryRequest is the JSON body POSTed to /api/query. Field names match
// the wire shape the app.js client sends; per-field meaning is
// documented on parsedQuery.
type queryRequest struct {
	Name        string `json:"name"`
	QType       string `json:"qtype"`
	QTypeRaw    string `json:"qtype_raw"`
	Upstream    string `json:"upstream"`
	UpstreamRaw string `json:"upstream_raw"`
	Transport   string `json:"transport"`
	TLSName     string `json:"tls_name"`
	DoHURL      string `json:"doh_url"`
	DO          bool   `json:"do"`
	CD          bool   `json:"cd"`
	RD          bool   `json:"rd"`
	EDNS        bool   `json:"edns"`
	ShowRaw     bool   `json:"show_raw"`
}

// queryResponse mirrors the JSON the /api/query handler returns on
// success. On error a separate {error: "..."} body is sent.
//
// Request and Response carry the dig-style formatted message — header,
// question section, and per-section records — for the actual wire
// message in each direction. RequestHex and ResponseHex carry the raw
// wire bytes as a hex string; they are populated only when the
// request set ShowRaw. HTTPRequest/HTTPResponse hold the dumped HTTP
// envelope (method/URL/status + headers) for DoH queries; they are
// empty for plain UDP/TCP/DoT.
type queryResponse struct {
	RCode        string       `json:"rcode"`
	Server       string       `json:"server"`
	ElapsedMs    int64        `json:"elapsed_ms"`
	Request      formattedMsg `json:"request"`
	Response     formattedMsg `json:"response"`
	RequestHex   string       `json:"request_hex,omitempty"`
	ResponseHex  string       `json:"response_hex,omitempty"`
	HTTPRequest  string       `json:"http_request,omitempty"`
	HTTPResponse string       `json:"http_response,omitempty"`
}

// formattedMsg is the structured view of a single DNS message,
// formatted for display.
type formattedMsg struct {
	ID         uint16   `json:"id"`
	Opcode     string   `json:"opcode"`
	RCode      string   `json:"rcode"`
	Flags      []string `json:"flags"`
	Counts     string   `json:"counts"`
	Question   []string `json:"question"`
	Answer     []string `json:"answer"`
	Authority  []string `json:"authority"`
	Additional []string `json:"additional"`
	EDNS       []string `json:"edns,omitempty"`
}

type transport string

const (
	transportUDP transport = "udp"
	transportTCP transport = "tcp"
	transportDoT transport = "dot"
	transportDoH transport = "doh"
)

// parsedQuery is the validated, post-mode-gate form of a /api/query
// request. Every field here is normalized — qtype is a real
// rrtype.Type, upstream is a parsed netip.AddrPort (zero for DoH where
// the address is in the URL), transport is one of the constants above.
type parsedQuery struct {
	name      wire.Name
	qtype     rrtype.Type
	upstream  netip.AddrPort
	transport transport
	tlsName   string
	dohURL    string
	do        bool
	cd        bool
	rd        bool
	edns      bool
	showRaw   bool
}

// parseQuery validates the JSON body and normalises every field. It
// does NOT enforce mode-specific allow-lists; the caller runs
// validateBasic afterwards in basic mode.
func parseQuery(req *queryRequest) (*parsedQuery, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, errors.New("name is required")
	}
	wireName, err := wire.ParseName(name)
	if err != nil {
		return nil, fmt.Errorf("parse name: %w", err)
	}

	qtStr := req.QType
	if s := strings.TrimSpace(req.QTypeRaw); s != "" {
		qtStr = s
	}
	if qtStr == "" {
		return nil, errors.New("qtype is required")
	}
	qt, ok := rrtype.Parse(qtStr)
	if !ok {
		return nil, fmt.Errorf("unknown rrtype %q", qtStr)
	}

	tr := transport(strings.ToLower(strings.TrimSpace(req.Transport)))
	if tr == "" {
		tr = transportUDP
	}
	switch tr {
	case transportUDP, transportTCP, transportDoT, transportDoH:
	default:
		return nil, fmt.Errorf("unknown transport %q", req.Transport)
	}

	var addr netip.AddrPort
	upstream := strings.TrimSpace(req.Upstream)
	if s := strings.TrimSpace(req.UpstreamRaw); s != "" {
		upstream = s
	}
	dohURL := strings.TrimSpace(req.DoHURL)

	// For DoH, upstream and doh_url are both optional individually,
	// but at least one must be present: with an upstream we look up
	// the URL in the well-known map, with an explicit URL we honour
	// it as-is. For UDP/TCP/DoT, upstream is mandatory.
	if upstream != "" {
		addr, err = parseUpstream(upstream, tr)
		if err != nil {
			return nil, err
		}
	} else if tr != transportDoH {
		return nil, errors.New("upstream is required")
	}
	if tr == transportDoH && dohURL == "" && !addr.IsValid() {
		return nil, errors.New("doh_url or upstream is required for DoH")
	}

	// The basic-mode dropdown ships upstreams as addr:53 (from
	// /etc/resolv.conf), but DoT speaks TLS on 853. If the user
	// picked DoT against a port-53 entry, silently switch to 853 so
	// they don't have to remember the right port — same behavior as
	// `dig +tls @host`. A non-53 port is treated as a deliberate
	// override and left alone.
	if tr == transportDoT && addr.IsValid() && addr.Port() == 53 {
		addr = netip.AddrPortFrom(addr.Addr(), 853)
	}

	return &parsedQuery{
		name:      wireName,
		qtype:     qt,
		upstream:  addr,
		transport: tr,
		tlsName:   strings.TrimSpace(req.TLSName),
		dohURL:    dohURL,
		do:        req.DO,
		cd:        req.CD,
		rd:        req.RD,
		edns:      req.EDNS,
		showRaw:   req.ShowRaw,
	}, nil
}

// parseUpstream accepts "host:port" or bare "host" and applies the
// transport's default port (53 for UDP/TCP, 853 for DoT). The host
// must be a literal IP address — basic mode rejects unresolved names
// to keep the trust boundary at the address, and advanced-mode use of
// names would silently introduce a recursive A/AAAA lookup against an
// arbitrary upstream which is not what the user typed.
func parseUpstream(s string, tr transport) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("upstream %q must be a literal IP[:port]", s)
	}
	port := uint16(53)
	if tr == transportDoT {
		port = 853
	}
	return netip.AddrPortFrom(addr, port), nil
}

// execute issues the parsed query against the chosen upstream and
// renders the response into a queryResponse. Request/response hex
// fields are populated only when q.showRaw is set.
func execute(ctx context.Context, q *parsedQuery) (*queryResponse, error) {
	inner, hTap, err := buildExchanger(q)
	if err != nil {
		return nil, fmt.Errorf("build exchanger: %w", err)
	}
	tap := &tapExchanger{inner: inner}

	r, err := acidns.NewResolver(
		acidns.WithExchanger(tap),
		acidns.WithDNSSEC(q.do),
		acidns.WithEDNS(q.edns),
	)
	if err != nil {
		return nil, fmt.Errorf("build resolver: %w", err)
	}

	start := time.Now()
	ans, err := r.Resolve(ctx, q.name, q.qtype)
	elapsed := time.Since(start)

	// A non-NoError RCODE is surfaced as a *RCodeError; the typed
	// answer is still available via ans.Answer(). We want to render
	// that exactly like the success path, just with the non-zero
	// RCODE in the header, so unwrap here rather than failing the
	// request.
	if err != nil {
		var rce *acidns.RCodeError
		if !errors.As(err, &rce) {
			return nil, err
		}
		ans = rce.Answer()
	}
	if ans == nil {
		return nil, errors.New("resolver returned no answer")
	}

	raw := ans.Raw()
	resp := &queryResponse{
		RCode:     raw.Flags().RCODE().String(),
		Server:    addrPortString(ans.Server(), q),
		ElapsedMs: elapsed.Milliseconds(),
		Response:  formatMessage(raw),
	}
	if tap.hasRequest {
		resp.Request = formatMessage(tap.request)
	}

	if q.showRaw {
		resp.RequestHex = tap.requestHex
		resp.ResponseHex = tap.responseHex
	}
	if hTap != nil {
		resp.HTTPRequest = hTap.requestText
		resp.HTTPResponse = hTap.responseText
	}

	return resp, nil
}

// buildExchanger constructs the leaf transport exchanger for q. The
// caller wraps the result in [tapExchanger] before threading it into
// the Resolver via WithExchanger.
//
// We always go through WithExchanger so the tap sits directly above
// the transport — that is the only point where the wire bytes are
// observable. The trade-off is that the UDP path here does NOT carry
// the WithServers-built TC=1 → TCP fallback. The web UI is an
// inspection tool; callers who need fallback semantics should use the
// CLI form or pick TCP/DoT/DoH explicitly.
//
// For DoH the returned *httpTap captures the HTTP envelope (method /
// URL / status / headers) as the request flows through the embedded
// http.Client. The tap is nil for all other transports because there
// is no analogous L7 envelope to show.
func buildExchanger(q *parsedQuery) (acidns.Exchanger, *httpTap, error) {
	switch q.transport {
	case transportDoH:
		url, ok := pickDoHURL(q.dohURL, q.upstream)
		if !ok {
			return nil, nil, fmt.Errorf("doh: no known DoH URL for upstream %s; provide doh_url explicitly", q.upstream)
		}
		tap := newHTTPTap(nil)
		hc := &http.Client{Transport: tap}
		ex, err := doh.NewClient(url, doh.WithHTTPClient(hc))
		if err != nil {
			return nil, nil, err
		}
		return ex, tap, nil
	case transportDoT:
		name, insecure := pickTLSName(q.tlsName, q.upstream)
		dotOpts := []dot.Option{dot.WithServerName(name)}
		if insecure {
			dotOpts = append(dotOpts, dot.WithInsecure(true))
		}
		ex, err := dot.NewClient(q.upstream, dotOpts...)
		return ex, nil, err
	case transportTCP:
		ex, err := acidns.NewTCPClient(q.upstream)
		return ex, nil, err
	default:
		ex, err := acidns.NewUDPClient(q.upstream)
		return ex, nil, err
	}
}

// tapExchanger wraps an Exchanger and snapshots both the outgoing
// query and the incoming response. It holds the full wire.Message in
// each direction so the handler can render the structured "actual
// message" form, and pre-encodes each to bytes for the optional hex
// view. wire.Pack produces the canonical form the transport itself
// sends, so the hex matches the on-the-wire bytes modulo
// compression-pointer choices that the parser already collapsed.
type tapExchanger struct {
	inner       acidns.Exchanger
	request     wire.Message
	response    wire.Message
	hasRequest  bool
	hasResponse bool
	requestHex  string
	responseHex string
}

func (t *tapExchanger) Exchange(ctx context.Context, q wire.Message) (wire.Message, error) {
	t.request = q
	t.hasRequest = true
	if b, err := wire.Pack(q); err == nil {
		t.requestHex = hex.EncodeToString(b)
	}
	resp, err := t.inner.Exchange(ctx, q)
	if err != nil {
		return resp, err
	}
	t.response = resp
	t.hasResponse = true
	if b, perr := wire.Pack(resp); perr == nil {
		t.responseHex = hex.EncodeToString(b)
	}
	return resp, nil
}

// addrPortString returns the immediate upstream the resolver reported
// it talked to, falling back to the request's upstream when the
// exchanger did not stamp one (e.g. DoH, where the addr is hidden
// behind the HTTP client). For DoH we re-derive the URL via
// pickDoHURL so the display reflects what the server actually used
// even when the user submitted a blank doh_url.
func addrPortString(reported netip.AddrPort, q *parsedQuery) string {
	if reported.IsValid() {
		return reported.String()
	}
	if q.transport == transportDoH {
		if url, ok := pickDoHURL(q.dohURL, q.upstream); ok {
			return url
		}
	}
	return q.upstream.String()
}
