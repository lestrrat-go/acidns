package dnscrypt_test

import (
	"bytes"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// decryptHelper / encryptHelper duplicate the dnscrypt package's
// internal logic (which lives behind the Client surface) for the
// fake-resolver test in dnscrypt_test.go.
func decryptHelper(sharedKey []byte, clientNonce [12]byte, ct []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(sharedKey)
	if err != nil {
		return nil, err
	}
	var nonce [24]byte
	copy(nonce[:12], clientNonce[:])
	plain, err := aead.Open(nil, nonce[:], ct, nil)
	if err != nil {
		return nil, err
	}
	return stripPad(plain)
}

func encryptHelper(sharedKey []byte, clientNonce, serverNonce [12]byte, plain []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(sharedKey)
	if err != nil {
		return nil, err
	}
	var nonce [24]byte
	copy(nonce[:12], clientNonce[:])
	copy(nonce[12:], serverNonce[:])
	padded := pad(plain)
	return aead.Seal(nil, nonce[:], padded, nil), nil
}

func pad(b []byte) []byte {
	out := append([]byte(nil), b...)
	out = append(out, 0x80)
	for len(out)%64 != 0 {
		out = append(out, 0)
	}
	return out
}

func stripPad(b []byte) ([]byte, error) {
	for i := len(b) - 1; i >= 0; i-- {
		switch b[i] {
		case 0x00:
			continue
		case 0x80:
			return b[:i], nil
		default:
			return nil, fmt.Errorf("bad pad")
		}
	}
	return nil, fmt.Errorf("no sentinel")
}

// silence unused-import lint when only one helper is referenced.
var _ = bytes.Equal
