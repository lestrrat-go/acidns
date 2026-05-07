package wire

import "fmt"

// Flags holds the second 16-bit word of a DNS header: QR, Opcode, AA, TC,
// RD, RA, Z, AD, CD, and RCODE. Accessor methods decode each subfield;
// With* methods return a modified copy.
type Flags uint16

const (
	flagQR uint16 = 1 << 15
	flagAA uint16 = 1 << 10
	flagTC uint16 = 1 << 9
	flagRD uint16 = 1 << 8
	flagRA uint16 = 1 << 7
	flagAD uint16 = 1 << 5
	flagCD uint16 = 1 << 4
)

// Opcode is the 4-bit DNS message opcode (RFC 1035 §4.1.1, RFC 6895).
type Opcode uint8

const (
	OpcodeQuery  Opcode = 0
	OpcodeIQuery Opcode = 1
	OpcodeStatus Opcode = 2
	OpcodeNotify Opcode = 4
	OpcodeUpdate Opcode = 5
	OpcodeDSO    Opcode = 6
)

func (o Opcode) String() string {
	switch o {
	case OpcodeQuery:
		return "QUERY"
	case OpcodeIQuery:
		return "IQUERY"
	case OpcodeStatus:
		return "STATUS"
	case OpcodeNotify:
		return "NOTIFY"
	case OpcodeUpdate:
		return "UPDATE"
	case OpcodeDSO:
		return "DSO"
	default:
		return fmt.Sprintf("OPCODE%d", uint8(o))
	}
}

// RCODE is the 4-bit DNS response code (RFC 1035 §4.1.1) including the
// extensions surfaced inside the standard header.
type RCODE uint8

const (
	RCODENoError  RCODE = 0
	RCODEFormErr  RCODE = 1
	RCODEServFail RCODE = 2
	RCODENXDomain RCODE = 3
	RCODENotImp   RCODE = 4
	RCODERefused  RCODE = 5
	RCODEYXDomain RCODE = 6
	RCODEYXRRSet  RCODE = 7
	RCODENXRRSet  RCODE = 8
	RCODENotAuth  RCODE = 9
	RCODENotZone  RCODE = 10
)

func (r RCODE) String() string {
	switch r {
	case RCODENoError:
		return "NOERROR"
	case RCODEFormErr:
		return "FORMERR"
	case RCODEServFail:
		return "SERVFAIL"
	case RCODENXDomain:
		return "NXDOMAIN"
	case RCODENotImp:
		return "NOTIMP"
	case RCODERefused:
		return "REFUSED"
	case RCODEYXDomain:
		return "YXDOMAIN"
	case RCODEYXRRSet:
		return "YXRRSET"
	case RCODENXRRSet:
		return "NXRRSET"
	case RCODENotAuth:
		return "NOTAUTH"
	case RCODENotZone:
		return "NOTZONE"
	default:
		return fmt.Sprintf("RCODE%d", uint8(r))
	}
}

func (f Flags) Response() bool           { return uint16(f)&flagQR != 0 }
func (f Flags) Opcode() Opcode           { return Opcode((uint16(f) >> 11) & 0x0f) }
func (f Flags) Authoritative() bool      { return uint16(f)&flagAA != 0 }
func (f Flags) Truncated() bool          { return uint16(f)&flagTC != 0 }
func (f Flags) RecursionDesired() bool   { return uint16(f)&flagRD != 0 }
func (f Flags) RecursionAvailable() bool { return uint16(f)&flagRA != 0 }
func (f Flags) AuthenticData() bool      { return uint16(f)&flagAD != 0 }
func (f Flags) CheckingDisabled() bool   { return uint16(f)&flagCD != 0 }
func (f Flags) RCODE() RCODE             { return RCODE(uint16(f) & 0x0f) }

func (f Flags) WithResponse(v bool) Flags           { return setBit(f, flagQR, v) }
func (f Flags) WithAuthoritative(v bool) Flags      { return setBit(f, flagAA, v) }
func (f Flags) WithTruncated(v bool) Flags          { return setBit(f, flagTC, v) }
func (f Flags) WithRecursionDesired(v bool) Flags   { return setBit(f, flagRD, v) }
func (f Flags) WithRecursionAvailable(v bool) Flags { return setBit(f, flagRA, v) }
func (f Flags) WithAuthenticData(v bool) Flags      { return setBit(f, flagAD, v) }
func (f Flags) WithCheckingDisabled(v bool) Flags   { return setBit(f, flagCD, v) }

func (f Flags) WithOpcode(o Opcode) Flags {
	return Flags((uint16(f) &^ (0x0f << 11)) | (uint16(o&0x0f) << 11))
}

func (f Flags) WithRCODE(r RCODE) Flags {
	return Flags((uint16(f) &^ 0x0f) | uint16(r&0x0f))
}

func setBit(f Flags, mask uint16, on bool) Flags {
	if on {
		return Flags(uint16(f) | mask)
	}
	return Flags(uint16(f) &^ mask)
}
