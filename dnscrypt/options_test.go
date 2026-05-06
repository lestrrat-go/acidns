package dnscrypt_test

import (
	"testing"
	"time"

	"github.com/lestrrat-go/acidns/dnscrypt"
)

func TestOptions(t *testing.T) {
	t.Parallel()
	// Just instantiate options to exercise their applyDNSCrypt funcs.
	_ = dnscrypt.WithTimeout(2 * time.Second)
}
