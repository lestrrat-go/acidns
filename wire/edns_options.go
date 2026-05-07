package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// EDNS option helpers per code, with typed parsers for common shapes.
// The wire-level EDNSOption interface is in edns.go; these wrappers expose
// each option as a strongly-typed Go value.

// NewNSID builds an NSID EDNS option (RFC 5001). On a query, identifier is
// typically empty; on a response, the server fills in its identifier bytes.
func NewNSID(identifier []byte) EDNSOption {
	cp := make([]byte, len(identifier))
	copy(cp, identifier)
	return ednsOption{code: EDNSOptionNSID, data: cp}
}

// NSIDIdentifier returns the identifier bytes carried by an NSID option, or
// false if o is not an NSID option.
func NSIDIdentifier(o EDNSOption) ([]byte, bool) {
	if o.Code() != EDNSOptionNSID {
		return nil, false
	}
	return o.Data(), true
}

// NewEDNSExpire builds an EDNS EXPIRE option (RFC 7314). On a query, the
// option carries no data; on a response from a secondary, it carries the
// remaining seconds until the secondary considers the zone expired.
func NewEDNSExpire(seconds uint32) EDNSOption {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], seconds)
	return ednsOption{code: EDNSOptionExpire, data: b[:]}
}

// NewEDNSExpireQuery builds an empty-payload EDNS EXPIRE option suitable for
// inclusion in a query (RFC 7314 §3 — query carries no data).
func NewEDNSExpireQuery() EDNSOption {
	return ednsOption{code: EDNSOptionExpire, data: nil}
}

// EDNSExpireSeconds returns the seconds value from an EDNS EXPIRE option;
// the boolean is false when o is not an EXPIRE option or carries an empty
// payload (a query EXPIRE option).
func EDNSExpireSeconds(o EDNSOption) (uint32, bool) {
	if o.Code() != EDNSOptionExpire || len(o.Data()) != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(o.Data()), true
}

// NewTCPKeepalive builds an edns-tcp-keepalive option (RFC 7828). A query
// uses an empty payload; a response from a server sets a timeout (in
// 100-millisecond units). Pass a zero duration to mean "no timeout
// preference advertised" (empty payload).
func NewTCPKeepalive(timeout time.Duration) EDNSOption {
	if timeout == 0 {
		return ednsOption{code: EDNSOptionTCPKeepalive, data: nil}
	}
	units := uint16(timeout / (100 * time.Millisecond))
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], units)
	return ednsOption{code: EDNSOptionTCPKeepalive, data: b[:]}
}

// TCPKeepaliveTimeout returns the timeout encoded in an edns-tcp-keepalive
// option, or false if o is not such an option or has an empty payload.
func TCPKeepaliveTimeout(o EDNSOption) (time.Duration, bool) {
	if o.Code() != EDNSOptionTCPKeepalive || len(o.Data()) != 2 {
		return 0, false
	}
	units := binary.BigEndian.Uint16(o.Data())
	return time.Duration(units) * 100 * time.Millisecond, true
}

// ClientSubnetFamily identifies the address family in an EDNS Client Subnet
// option (RFC 7871). 1 = IPv4, 2 = IPv6.
type ClientSubnetFamily uint16

const (
	ClientSubnetIPv4 ClientSubnetFamily = 1
	ClientSubnetIPv6 ClientSubnetFamily = 2
)

// NewClientSubnet builds an EDNS Client Subnet option (RFC 7871). source is
// the source prefix length (the privacy-bounded prefix length the requestor
// wants the server to consider); scope is 0 in queries. The address bytes
// trailing the source prefix length are zero-padded on the wire.
func NewClientSubnet(prefix netip.Prefix, scope uint8) (EDNSOption, error) {
	if !prefix.IsValid() {
		return nil, fmt.Errorf("%w: ClientSubnet prefix invalid", ErrInvalidMessage)
	}
	family := ClientSubnetIPv4
	var addr []byte
	if prefix.Addr().Is6() {
		family = ClientSubnetIPv6
		b := prefix.Addr().As16()
		addr = b[:]
	} else {
		b := prefix.Addr().As4()
		addr = b[:]
	}
	source := uint8(prefix.Bits())
	// Truncate to ceil(source/8) bytes per RFC 7871 §6.
	addrLen := (int(source) + 7) / 8
	if addrLen > len(addr) {
		return nil, fmt.Errorf("%w: ClientSubnet source %d exceeds address width", ErrInvalidMessage, source)
	}
	data := make([]byte, 4+addrLen)
	binary.BigEndian.PutUint16(data[0:], uint16(family))
	data[2] = source
	data[3] = scope
	copy(data[4:], addr[:addrLen])
	return ednsOption{code: EDNSOptionClientSubnet, data: data}, nil
}

// ClientSubnet decodes an ECS option into family, prefix, and scope. The
// boolean is false if o is not an ECS option or is malformed.
func ClientSubnet(o EDNSOption) (netip.Prefix, uint8, bool) {
	if o.Code() != EDNSOptionClientSubnet || len(o.Data()) < 4 {
		return netip.Prefix{}, 0, false
	}
	d := o.Data()
	family := ClientSubnetFamily(binary.BigEndian.Uint16(d[0:]))
	source := d[2]
	scope := d[3]
	addr := d[4:]
	switch family {
	case ClientSubnetIPv4:
		var b [4]byte
		copy(b[:], addr)
		return netip.PrefixFrom(netip.AddrFrom4(b), int(source)), scope, true
	case ClientSubnetIPv6:
		var b [16]byte
		copy(b[:], addr)
		return netip.PrefixFrom(netip.AddrFrom16(b), int(source)), scope, true
	default:
		return netip.Prefix{}, 0, false
	}
}

// ErrInvalidCookie is returned when a DNS cookie has an unexpected length.
var ErrInvalidCookie = errors.New("dnsmsg: invalid DNS cookie")

// NewClientCookie builds a query-side DNS cookie option (RFC 7873). The
// client cookie MUST be exactly 8 bytes.
func NewClientCookie(clientCookie [8]byte) EDNSOption {
	data := append([]byte(nil), clientCookie[:]...)
	return ednsOption{code: EDNSOptionCookie, data: data}
}

// NewClientServerCookie builds a DNS cookie option that includes both the
// client cookie (8 bytes) and the server cookie (8–32 bytes), per
// RFC 7873 §4 / RFC 9018 §2.
func NewClientServerCookie(clientCookie [8]byte, serverCookie []byte) (EDNSOption, error) {
	if len(serverCookie) < 8 || len(serverCookie) > 32 {
		return nil, fmt.Errorf("%w: server cookie length %d not in [8,32]", ErrInvalidCookie, len(serverCookie))
	}
	data := make([]byte, 0, 8+len(serverCookie))
	data = append(data, clientCookie[:]...)
	data = append(data, serverCookie...)
	return ednsOption{code: EDNSOptionCookie, data: data}, nil
}

// Cookies decodes an RFC 7873 cookie option. The server cookie may be empty.
// Returns false if o is not a cookie option or is malformed.
func Cookies(o EDNSOption) (clientCookie [8]byte, serverCookie []byte, ok bool) {
	if o.Code() != EDNSOptionCookie {
		return clientCookie, nil, false
	}
	d := o.Data()
	if len(d) != 8 && (len(d) < 16 || len(d) > 40) {
		return clientCookie, nil, false
	}
	copy(clientCookie[:], d[:8])
	if len(d) > 8 {
		serverCookie = append([]byte(nil), d[8:]...)
	}
	return clientCookie, serverCookie, true
}

// ExtendedErrorCode names an Extended DNS Error info-code (RFC 8914 §4 and
// the IANA Extended DNS Error registry).
type ExtendedErrorCode uint16

const (
	ExtendedErrorOther                ExtendedErrorCode = 0
	ExtendedErrorUnsupportedDNSKEYAlg ExtendedErrorCode = 1
	ExtendedErrorUnsupportedDSDigest  ExtendedErrorCode = 2
	ExtendedErrorStaleAnswer          ExtendedErrorCode = 3
	ExtendedErrorForgedAnswer         ExtendedErrorCode = 4
	ExtendedErrorDNSSECIndeterminate  ExtendedErrorCode = 5
	ExtendedErrorDNSSECBogus          ExtendedErrorCode = 6
	ExtendedErrorSignatureExpired     ExtendedErrorCode = 7
	ExtendedErrorSignatureNotYetValid ExtendedErrorCode = 8
	ExtendedErrorDNSKEYMissing        ExtendedErrorCode = 9
	ExtendedErrorRRSIGsMissing        ExtendedErrorCode = 10
	ExtendedErrorNoZoneKeyBitSet      ExtendedErrorCode = 11
	ExtendedErrorNSECMissing          ExtendedErrorCode = 12
	ExtendedErrorCachedError          ExtendedErrorCode = 13
	ExtendedErrorNotReady             ExtendedErrorCode = 14
	ExtendedErrorBlocked              ExtendedErrorCode = 15
	ExtendedErrorCensored             ExtendedErrorCode = 16
	ExtendedErrorFiltered             ExtendedErrorCode = 17
	ExtendedErrorProhibited           ExtendedErrorCode = 18
	ExtendedErrorStaleNXDomainAnswer  ExtendedErrorCode = 19
	ExtendedErrorNotAuthoritative     ExtendedErrorCode = 20
	ExtendedErrorNotSupported         ExtendedErrorCode = 21
	ExtendedErrorNoReachableAuthority ExtendedErrorCode = 22
	ExtendedErrorNetworkError         ExtendedErrorCode = 23
	ExtendedErrorInvalidData          ExtendedErrorCode = 24
)

// NewExtendedError builds an Extended DNS Error option (RFC 8914). extraText
// is informational and may be empty.
func NewExtendedError(code ExtendedErrorCode, extraText string) EDNSOption {
	data := make([]byte, 2+len(extraText))
	binary.BigEndian.PutUint16(data[0:], uint16(code))
	copy(data[2:], extraText)
	return ednsOption{code: EDNSOptionExtendedDNS, data: data}
}

// ExtendedError decodes an EDE option. Returns false if o is not an EDE
// option or is malformed.
func ExtendedError(o EDNSOption) (ExtendedErrorCode, string, bool) {
	if o.Code() != EDNSOptionExtendedDNS || len(o.Data()) < 2 {
		return 0, "", false
	}
	d := o.Data()
	return ExtendedErrorCode(binary.BigEndian.Uint16(d[0:])), string(d[2:]), true
}

// EDNSOptionZoneVersion is the IANA-assigned EDNS option code for ZONEVERSION
// (RFC 9660).
const EDNSOptionZoneVersion uint16 = 19

// ZoneVersionType identifies the version-encoding used in a ZONEVERSION
// option (RFC 9660 §2.2).
type ZoneVersionType uint8

const (
	// ZoneVersionTypeSOASerial is type 0: VERSION is the 4-byte big-endian
	// SOA serial of the zone for which the answer is authoritative.
	ZoneVersionTypeSOASerial ZoneVersionType = 0
)

// NewZoneVersionQuery builds a query-side ZONEVERSION option (empty payload),
// signalling the requestor would like the responder to include zone version
// information in the response.
func NewZoneVersionQuery() EDNSOption {
	return ednsOption{code: EDNSOptionZoneVersion, data: nil}
}

// NewZoneVersionSOASerial builds a response-side ZONEVERSION option carrying
// the SOA serial for the matched zone, with labelCount labels copied from
// the query name.
func NewZoneVersionSOASerial(labelCount uint8, serial uint32) EDNSOption {
	var b [6]byte
	b[0] = labelCount
	b[1] = uint8(ZoneVersionTypeSOASerial)
	binary.BigEndian.PutUint32(b[2:], serial)
	return ednsOption{code: EDNSOptionZoneVersion, data: b[:]}
}

// ZoneVersionSOASerial decodes a SOA-serial-typed ZONEVERSION option.
// Returns false if o is not a ZONEVERSION option, the type byte is not
// SOASerial, or the payload is malformed.
func ZoneVersionSOASerial(o EDNSOption) (labelCount uint8, serial uint32, ok bool) {
	if o.Code() != EDNSOptionZoneVersion || len(o.Data()) != 6 {
		return 0, 0, false
	}
	d := o.Data()
	if ZoneVersionType(d[1]) != ZoneVersionTypeSOASerial {
		return 0, 0, false
	}
	return d[0], binary.BigEndian.Uint32(d[2:]), true
}
