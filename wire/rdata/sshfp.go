package rdata

import (
	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// SSHFPAlgorithm names an SSH key algorithm carried in an SSHFP record
// (RFC 4255 / IANA SSHFP RR Types).
type SSHFPAlgorithm uint8

const (
	SSHFPAlgRSA     SSHFPAlgorithm = 1
	SSHFPAlgDSA     SSHFPAlgorithm = 2
	SSHFPAlgECDSA   SSHFPAlgorithm = 3
	SSHFPAlgED25519 SSHFPAlgorithm = 4
	SSHFPAlgED448   SSHFPAlgorithm = 6
)

// SSHFPType names a fingerprint type.
type SSHFPType uint8

const (
	SSHFPTypeSHA1   SSHFPType = 1
	SSHFPTypeSHA256 SSHFPType = 2
)

// SSHFP is the SSH key fingerprint rdata (RFC 4255).
type SSHFP interface {
	RData
	Algorithm() SSHFPAlgorithm
	FingerprintType() SSHFPType
	Fingerprint() []byte
}

type sshfp struct {
	alg   SSHFPAlgorithm
	fpt   SSHFPType
	value []byte
}

func (sshfp) Type() rrtype.Type            { return rrtype.SSHFP }
func (s sshfp) Algorithm() SSHFPAlgorithm  { return s.alg }
func (s sshfp) FingerprintType() SSHFPType { return s.fpt }
func (s sshfp) Fingerprint() []byte        { return s.value }
func (s sshfp) Pack(p *wirebb.Packer) {
	p.Uint8(uint8(s.alg))
	p.Uint8(uint8(s.fpt))
	p.Raw(s.value)
}

// NewSSHFP returns an SSHFP rdata.
func NewSSHFP(alg SSHFPAlgorithm, fpt SSHFPType, fingerprint []byte) SSHFP {
	cp := make([]byte, len(fingerprint))
	copy(cp, fingerprint)
	return sshfp{alg: alg, fpt: fpt, value: cp}
}

func unpackSSHFP(u *wirebb.Unpacker, rdlen int) (SSHFP, error) {
	alg, err := u.Uint8()
	if err != nil {
		return nil, err
	}
	fpt, err := u.Uint8()
	if err != nil {
		return nil, err
	}
	fp, err := u.Bytes(rdlen - 2)
	if err != nil {
		return nil, err
	}
	cp := make([]byte, len(fp))
	copy(cp, fp)
	return sshfp{alg: SSHFPAlgorithm(alg), fpt: SSHFPType(fpt), value: cp}, nil
}
