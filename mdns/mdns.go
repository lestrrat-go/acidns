// Package mdns implements multicast DNS (RFC 6762) and the subset of
// DNS-Service Discovery (RFC 6763) used to browse and resolve services
// on the local link.
//
// The package is intentionally minimal — Browse and Resolve cover the
// service-discovery use cases; service announcement (Publish) is out of
// scope for this version. The wire format reuses dnsmsg, so unit tests
// for query/response synthesis run without any network at all.
package mdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/lestrrat-go/acidns/dnsmsg"
	"github.com/lestrrat-go/acidns/dnsmsg/rdata"
	"github.com/lestrrat-go/acidns/dnsmsg/rrtype"
	"github.com/lestrrat-go/acidns/dnsname"
)

// Default mDNS link-local addresses (RFC 6762 §3).
const (
	Port    = 5353
	GroupV4 = "224.0.0.251"
	GroupV6 = "ff02::fb"
)

// LocalDomain is the special-use suffix that mDNS responders own.
var LocalDomain = dnsname.MustParse("local")

// ErrNoResponse is returned when Browse or Resolve produces no answers
// within the configured deadline.
var ErrNoResponse = errors.New("mdns: no responses received")

// Service is a single discovered instance.
type Service struct {
	// Instance name (the "Foo Bar" part of "Foo Bar._http._tcp.local.").
	Instance string
	// Service type ("_http._tcp.local.").
	Type     dnsname.Name
	Host     dnsname.Name
	Port     uint16
	Priority uint16
	Weight   uint16
	Addrs    []netip.Addr
	Text     map[string]string
	TTL      time.Duration
}

// BuildBrowseQuery constructs a PTR query for the given service type
// (e.g. "_http._tcp" or "_http._tcp.local"). The result can be marshalled
// directly and sent via any UDP path.
func BuildBrowseQuery(service string) (dnsmsg.Message, error) {
	name, err := serviceName(service)
	if err != nil {
		return nil, err
	}
	return dnsmsg.NewBuilder().
		ID(0). // RFC 6762 §18.1 — mDNS requests use ID 0.
		RecursionDesired(false).
		Question(dnsmsg.NewQuestion(name, rrtype.PTR)).
		Build()
}

// ParseBrowseResponse extracts the Service entries described by a single
// mDNS response. Multiple responses may need to be merged by the caller
// (additional sections from later responses can fill in addresses for
// hosts whose SRV came in earlier).
func ParseBrowseResponse(m dnsmsg.Message) []Service {
	srvByOwner := map[string]rdata.SRV{}
	srvTTLs := map[string]time.Duration{}
	txtByOwner := map[string][]string{}
	addrsByHost := map[string][]netip.Addr{}

	scanner := func(rec dnsmsg.Record) {
		key := rec.Name().String()
		switch rec.Type() {
		case rrtype.SRV:
			if s, ok := rec.RData().(rdata.SRV); ok {
				srvByOwner[key] = s
				srvTTLs[key] = rec.TTL()
			}
		case rrtype.TXT:
			if t, ok := rec.RData().(rdata.TXT); ok {
				txtByOwner[key] = append(txtByOwner[key], t.Strings()...)
			}
		case rrtype.A:
			if a, ok := rec.RData().(rdata.A); ok {
				addrsByHost[key] = append(addrsByHost[key], a.Addr())
			}
		case rrtype.AAAA:
			if a, ok := rec.RData().(rdata.AAAA); ok {
				addrsByHost[key] = append(addrsByHost[key], a.Addr())
			}
		}
	}
	for _, rec := range m.Answers() {
		scanner(rec)
	}
	for _, rec := range m.Additionals() {
		scanner(rec)
	}

	var out []Service
	for _, rec := range m.Answers() {
		if rec.Type() != rrtype.PTR {
			continue
		}
		ptr, ok := rec.RData().(rdata.PTR)
		if !ok {
			continue
		}
		instanceName := ptr.PtrDName()
		key := instanceName.String()
		s := srvByOwner[key]
		if s == nil {
			continue
		}
		svc := Service{
			Instance: leadingLabel(instanceName),
			Type:     rec.Name(),
			Host:     s.Target(),
			Port:     s.Port(),
			Priority: s.Priority(),
			Weight:   s.Weight(),
			Addrs:    append([]netip.Addr(nil), addrsByHost[s.Target().String()]...),
			Text:     parseTXT(txtByOwner[key]),
			TTL:      srvTTLs[key],
		}
		out = append(out, svc)
	}
	return out
}

// Browse sends a multicast PTR query for the named service type and
// collects responses for at most timeout. It deduplicates services by
// (instance, type) across responses.
func Browse(ctx context.Context, service string, timeout time.Duration) ([]Service, error) {
	q, err := BuildBrowseQuery(service)
	if err != nil {
		return nil, err
	}
	wire, err := dnsmsg.Marshal(q)
	if err != nil {
		return nil, err
	}

	conn, err := openMulticast()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	dst := &net.UDPAddr{IP: net.ParseIP(GroupV4), Port: Port}
	if _, err := conn.WriteTo(wire, dst); err != nil {
		return nil, fmt.Errorf("mdns: send: %w", err)
	}

	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetReadDeadline(deadline)

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-stop:
		}
	}()

	merged := map[string]Service{}
	buf := make([]byte, 9000)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}
		resp, err := dnsmsg.Unmarshal(buf[:n])
		if err != nil {
			continue
		}
		for _, svc := range ParseBrowseResponse(resp) {
			key := svc.Instance + "|" + svc.Type.String()
			merged[key] = svc
		}
	}
	if len(merged) == 0 {
		return nil, ErrNoResponse
	}
	out := make([]Service, 0, len(merged))
	for _, s := range merged {
		out = append(out, s)
	}
	return out, nil
}

func openMulticast() (*net.UDPConn, error) {
	addr := &net.UDPAddr{IP: net.ParseIP(GroupV4), Port: Port}
	return net.ListenMulticastUDP("udp4", nil, addr)
}

// serviceName normalises a user-supplied service spec. Accepts "_http._tcp",
// "_http._tcp.local", or "_http._tcp.local." and returns the wire form.
func serviceName(service string) (dnsname.Name, error) {
	s := strings.TrimSuffix(service, ".")
	if !strings.HasSuffix(s, ".local") {
		s = s + ".local"
	}
	return dnsname.Parse(s)
}

func leadingLabel(n dnsname.Name) string {
	for l := range n.Labels() {
		return string(l)
	}
	return ""
}

// parseTXT decodes service-discovery key-value pairs from TXT strings
// per RFC 6763 §6.
func parseTXT(strs []string) map[string]string {
	out := map[string]string{}
	for _, s := range strs {
		if i := strings.IndexByte(s, '='); i >= 0 {
			out[s[:i]] = s[i+1:]
		} else if s != "" {
			out[s] = ""
		}
	}
	return out
}
