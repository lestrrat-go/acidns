package rdata

import (
	"slices"

	"github.com/lestrrat-go/acidns/wire/rrtype"
	"github.com/lestrrat-go/acidns/wire/wirebb"
)

// OPENPGPKEY is the OpenPGP public-key rdata (RFC 7929 §2.1). The payload
// is the OpenPGP transferable public key in binary (RFC 4880) form — the
// rdata wire format carries no internal framing.
type OPENPGPKEY struct{ pubkey []byte }

func (OPENPGPKEY) Type() rrtype.Type       { return rrtype.OPENPGPKEY }
func (OPENPGPKEY) typedRData()             {}
func (k OPENPGPKEY) PublicKey() []byte     { return slices.Clone(k.pubkey) }
func (k OPENPGPKEY) Pack(p *wirebb.Packer) { p.Raw(k.pubkey) }

// NewOPENPGPKEY returns an OPENPGPKEY rdata. The argument is copied; the
// caller may safely mutate the input slice afterwards.
func NewOPENPGPKEY(pubkey []byte) OPENPGPKEY {
	cp := make([]byte, len(pubkey))
	copy(cp, pubkey)
	return OPENPGPKEY{pubkey: cp}
}

func unpackOPENPGPKEY(u *wirebb.Unpacker, rdlen int) (OPENPGPKEY, error) {
	var zero OPENPGPKEY
	b, err := u.Bytes(rdlen)
	if err != nil {
		return zero, err
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return OPENPGPKEY{pubkey: cp}, nil
}
