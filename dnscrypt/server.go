package dnscrypt

// DNSCrypt v2 server. Listens on UDP, accepts encrypted query
// packets that match the active certificate's ClientMagic, decrypts
// them, dispatches to the supplied [acidns.Handler], and ships the
// encrypted response back. The protocol does not run over TCP — TCP
// support in the spec is optional and out of scope here.
//
// # Resolver-side material
//
// A DNSCrypt server needs:
//
//   - A signed [Cert] (resolver short-term public key, validity
//     window, ClientMagic). Construct with [NewCert] + [SignCert],
//     or generate via [GenerateServerMaterial].
//   - The matching resolver short-term private key (X25519 32-byte
//     scalar). The same key that produced the cert's ResolverPK MUST
//     be supplied — there is no other binding between cert and key.
//
// Certificates rotate; a real DNSCrypt server typically advertises
// the current cert (signed by its long-term provider key) in a TXT
// record at the resolver name and rotates short-term keys hourly.
// This package's [Server] takes one cert+key pair at construction
// and serves under that pair until ctx is cancelled. To rotate,
// build a fresh Server with a new cert and Run it on a new socket;
// graceful key roll is the operator's responsibility.

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/lestrrat-go/acidns"
	"github.com/lestrrat-go/acidns/internal/serverctl"
	"github.com/lestrrat-go/acidns/wire"
)

// ErrServerClosed is recorded on the [ServerController] after a
// clean shutdown via context cancellation.
var ErrServerClosed = errors.New("dnscrypt: server closed")

// Server is an immutable configuration carrier for a DNSCrypt
// server. The bound cert + resolver private key live here; runtime
// state lives entirely on the [*ServerController] returned by
// [Server.Run].
type Server struct {
	addr       netip.AddrPort
	handler    acidns.Handler
	cert       *Cert
	resolverSK [32]byte
	cfg        serverConfig
}

// NewServer validates the configuration. It does NOT bind a socket;
// pass the result to [Server.Run] to start serving.
//
// The supplied cert MUST already be signed (via [SignCert]) — the
// server does not re-sign it. The resolver short-term private key is
// supplied via [WithResolverSecretKey] and is required; NewServer
// returns an error when the option is omitted or set to the zero
// value. The key MUST be the X25519 scalar whose public form is
// cert.ResolverPK; the package cannot verify this binding (signed
// material is opaque) so a mismatch silently produces undecryptable
// responses.
func NewServer(addr netip.AddrPort, h acidns.Handler, opts ...ServerOption) (*Server, error) {
	if h == nil {
		return nil, fmt.Errorf("dnscrypt: handler is nil")
	}
	cfg := serverConfig{
		bufferSize:   4096,
		maxInflight:  256,
		writeTimeout: 5 * time.Second,
		now:          time.Now,
	}
	for _, o := range opts {
		o.applyDNSCryptServer(&cfg)
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	if cfg.cert == nil {
		return nil, fmt.Errorf("dnscrypt: NewServer requires WithCert")
	}
	if cfg.cert.esVersion != ESVersion2 {
		return nil, fmt.Errorf("%w: ES%d (only ES%d is implemented)", ErrUnsupportedESVersion, cfg.cert.esVersion, ESVersion2)
	}
	if !cfg.resolverSKSet {
		return nil, fmt.Errorf("dnscrypt: NewServer requires WithResolverSecretKey")
	}
	var zero [32]byte
	if subtle.ConstantTimeCompare(cfg.resolverSK[:], zero[:]) == 1 {
		return nil, fmt.Errorf("dnscrypt: resolver secret key is zero")
	}
	return &Server{
		addr:       addr,
		handler:    h,
		cert:       cfg.cert,
		resolverSK: cfg.resolverSK,
		cfg:        cfg,
	}, nil
}

// Run binds a fresh UDP socket and spawns the dispatch goroutine.
// Cancelling ctx is the only way to stop the instance.
func (s *Server) Run(ctx context.Context) (*ServerController, error) {
	now := s.cfg.now()
	if now.Before(s.cert.validFrom) || now.After(s.cert.validUntil) {
		return nil, fmt.Errorf("%w: now=%s window=[%s, %s]",
			ErrCertExpired, now, s.cert.validFrom, s.cert.validUntil)
	}
	pc, err := net.ListenPacket("udp", s.addr.String()) //nolint:noctx // socket lifetime is bound to Run's ctx
	if err != nil {
		return nil, fmt.Errorf("dnscrypt: listen %s: %w", s.addr, err)
	}
	la, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = pc.Close()
		return nil, fmt.Errorf("dnscrypt: listen %s: unexpected addr type %T", s.addr, pc.LocalAddr())
	}
	bound := netip.AddrPortFrom(la.AddrPort().Addr(), uint16(la.Port))

	loop := &serverLoop{
		pc:      pc,
		addr:    bound,
		handler: s.handler,
		cfg:     s.cfg,
	}
	loop.material.Store(&keyMaterial{cert: s.cert, resolverSK: s.resolverSK})
	if s.cfg.maxInflight > 0 {
		loop.sem = make(chan struct{}, s.cfg.maxInflight)
	}
	loop.bufPool.New = func() any {
		b := make([]byte, s.cfg.bufferSize)
		return &b
	}

	ctrl := &ServerController{
		Core: serverctl.New(bound),
		loop: loop,
	}
	go func() {
		defer ctrl.CloseDone()
		err := loop.run(ctx)
		if err != nil && !errors.Is(err, ErrServerClosed) {
			ctrl.SetErr(err)
		}
	}()
	return ctrl, nil
}

// keyMaterial pairs the active cert with its matching resolver
// private key. Stored under [serverLoop.material] as a single atomic
// pointer so a hot rotation swaps both halves at once — using two
// independent atomics would expose a window where the cert and key
// disagree.
type keyMaterial struct {
	cert       *Cert
	resolverSK [32]byte
}

// ServerController is the runtime handle returned by [Server.Run].
// The name is prefixed Server because the dnscrypt package's other
// long-lived runtime type is the client [Cert]; ambiguity is worse
// than verbosity here. Embeds [serverctl.Core] (Addr / Done / Err /
// Wait); dnscrypt-specific runtime queries (Rotate) belong on this
// type.
type ServerController struct {
	serverctl.Core
	loop *serverLoop
}

// Rotate swaps the active certificate and resolver short-term key
// on the running server. Useful for the standard DNSCrypt operator
// pattern of rotating short-term keys (and the cert that advertises
// the new public key) on a regular cadence — typically hourly —
// without re-binding the UDP socket.
//
// The swap is atomic: in-flight handlers using the old material
// finish under it; new packets arriving after Rotate returns are
// decrypted under the new material. Returns an error if the new
// cert is missing or outside its validity window; the previous
// material remains active in that case.
func (c *ServerController) Rotate(cert *Cert, resolverSK [32]byte) error {
	if cert == nil {
		return fmt.Errorf("dnscrypt: Rotate: cert is nil")
	}
	if cert.esVersion != ESVersion2 {
		return fmt.Errorf("%w: ES%d", ErrUnsupportedESVersion, cert.esVersion)
	}
	// Mirror NewServer's zero-key reject — Rotate previously skipped
	// this and accepted the zero array silently, installing a useless
	// secret key whose corresponding X25519(zero, anything) shared
	// secret is the all-zero scalar that handshake counterparts reject.
	var zero [32]byte
	if subtle.ConstantTimeCompare(resolverSK[:], zero[:]) == 1 {
		return fmt.Errorf("dnscrypt: Rotate: resolver secret key is zero")
	}
	now := c.loop.cfg.now()
	if now.Before(cert.validFrom) || now.After(cert.validUntil) {
		return fmt.Errorf("%w: now=%s window=[%s, %s]",
			ErrCertExpired, now, cert.validFrom, cert.validUntil)
	}
	c.loop.material.Store(&keyMaterial{cert: cert, resolverSK: resolverSK})
	return nil
}

type serverLoop struct {
	pc       net.PacketConn
	addr     netip.AddrPort
	handler  acidns.Handler
	cfg      serverConfig
	material atomic.Pointer[keyMaterial]
	sem      chan struct{}
	bufPool  sync.Pool
	wg       sync.WaitGroup
	// writeMu serialises (SetWriteDeadline, WriteTo) on the shared
	// PacketConn across handler goroutines. Without it concurrent
	// writers can clobber each other's deadlines, producing spurious
	// deadline-exceeded errors that look like network failures.
	writeMu sync.Mutex
}

func (l *serverLoop) run(ctx context.Context) error {
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = l.pc.Close()
		case <-stop:
		}
	}()

	defer l.wg.Wait()

	for {
		bufp, _ := l.bufPool.Get().(*[]byte)
		buf := *bufp
		n, src, err := l.pc.ReadFrom(buf)
		if err != nil {
			l.bufPool.Put(bufp)
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return ErrServerClosed
			}
			return fmt.Errorf("dnscrypt: read: %w", err)
		}

		ua, ok := src.(*net.UDPAddr)
		if !ok {
			l.bufPool.Put(bufp)
			continue
		}
		// ClientMagic prefix-gate runs BEFORE acquiring an inflight
		// slot. Each accepted packet performs an X25519 +
		// ChaCha20-Poly1305 Open, so without this gate a junk-flood
		// attacker who knows nothing about the cert can still occupy
		// every inflight slot and force legitimate clients to drop.
		// The compare is constant-time (the ClientMagic is the
		// secret-ish discriminator that any prefix-timing oracle would
		// otherwise leak); inside the goroutine we skip the redundant
		// re-check via the prefix-checked flag.
		if n < 8 {
			l.bufPool.Put(bufp)
			continue
		}
		mat := l.material.Load()
		if mat == nil {
			l.bufPool.Put(bufp)
			continue
		}
		if subtle.ConstantTimeCompare((*bufp)[0:8], mat.cert.clientMagic[:]) != 1 {
			l.bufPool.Put(bufp)
			continue
		}
		if l.sem != nil {
			select {
			case l.sem <- struct{}{}:
			default:
				l.bufPool.Put(bufp)
				continue
			}
		}
		l.wg.Add(1)
		go func(bufp *[]byte, n int, src netip.AddrPort) {
			defer func() {
				l.bufPool.Put(bufp)
				if l.sem != nil {
					<-l.sem
				}
				l.wg.Done()
			}()
			l.handlePacket(ctx, (*bufp)[:n], src)
		}(bufp, n, ua.AddrPort())
	}
}

// handlePacket validates, decrypts, dispatches and re-encrypts a
// single DNSCrypt v2 packet. Malformed or wrong-magic packets are
// dropped silently — DNSCrypt has no provision for replying to a
// peer that hasn't proven it knows the current ClientMagic, since
// any such reply would be both useless and a small amplification.
func (l *serverLoop) handlePacket(ctx context.Context, body []byte, src netip.AddrPort) {
	// Layout: <ClientMagic 8> <ClientPK 32> <Nonce 12> <ciphertext>.
	if len(body) < 8+32+12+chacha20poly1305.Overhead {
		return
	}
	// Snapshot the active key material once per packet. After Rotate
	// the next packet picks up the new material; in-flight handlers
	// continue under whatever they read here.
	mat := l.material.Load()
	if mat == nil {
		return
	}
	// Constant-time: ClientMagic is the secret-ish discriminator that
	// gates whether to spend X25519+AEAD work on a packet; a timing
	// oracle on the prefix would let an attacker iteratively learn it.
	if subtle.ConstantTimeCompare(body[0:8], mat.cert.clientMagic[:]) != 1 {
		return
	}
	var clientPK [32]byte
	copy(clientPK[:], body[8:40])
	var clientNonce [12]byte
	copy(clientNonce[:], body[40:52])
	ct := body[52:]

	shared, err := sharedKey(clientPK, mat.resolverSK)
	if err != nil {
		return
	}
	aead, err := chacha20poly1305.NewX(shared[:])
	if err != nil {
		return
	}
	var fullNonce [24]byte
	copy(fullNonce[:12], clientNonce[:])
	plain, err := aead.Open(nil, fullNonce[:], ct, nil)
	if err != nil {
		return
	}
	queryBytes, err := unpad(plain)
	if err != nil {
		return
	}
	q, err := wire.Unmarshal(queryBytes)
	if err != nil {
		return
	}

	w := &responseWriter{
		pc:           l.pc,
		dst:          src,
		local:        l.addr,
		clientNonce:  clientNonce,
		aead:         aead,
		writeTimeout: l.cfg.writeTimeout,
		writeMu:      &l.writeMu,
	}
	_ = shared // referenced via aead's bound key
	switch verdict, reply := acidns.PreflightRequest(q); verdict {
	case acidns.PreflightDrop:
		return
	case acidns.PreflightReply:
			_ = w.WriteMsg(reply)
		return
	}
	l.handler.ServeDNS(ctx, w, q)
}

// responseWriter implements [acidns.ResponseWriter] over a single
// DNSCrypt v2 datagram exchange. Each WriteMsg call encrypts the
// response and ships it back to the client; subsequent calls are
// rejected because UDP carries one response per query.
type responseWriter struct {
	pc           net.PacketConn
	dst          netip.AddrPort
	local        netip.AddrPort
	clientNonce  [12]byte
	aead         cipher.AEAD
	writeTimeout time.Duration
	writeMu      *sync.Mutex
	wrote        bool
}

func (w *responseWriter) RemoteAddr() netip.AddrPort { return w.dst }
func (w *responseWriter) LocalAddr() netip.AddrPort  { return w.local }
func (w *responseWriter) Network() string            { return "dnscrypt" }

func (w *responseWriter) WriteMsg(m wire.Message) error {
	if w.wrote {
		return fmt.Errorf("dnscrypt: WriteMsg called twice on a single response")
	}
	w.wrote = true

	plain, err := wire.Marshal(m)
	if err != nil {
		return err
	}
	padded := pad(plain)

	var resolverNonce [12]byte
	if _, err := rand.Read(resolverNonce[:]); err != nil {
		return fmt.Errorf("dnscrypt: rand: %w", err)
	}
	var fullNonce [24]byte
	copy(fullNonce[:12], w.clientNonce[:])
	copy(fullNonce[12:], resolverNonce[:])

	ct := w.aead.Seal(nil, fullNonce[:], padded, nil)

	out := make([]byte, 0, 8+12+12+len(ct))
	out = append(out, resolverMagic[:]...)
	out = append(out, w.clientNonce[:]...)
	out = append(out, resolverNonce[:]...)
	out = append(out, ct...)

	udst := net.UDPAddrFromAddrPort(w.dst)
	// Bound the write so a saturated socket buffer or a kernel that
	// silently drops outbound traffic for the destination cannot pin
	// this handler goroutine indefinitely. Mirrors UDP/TCP/DoT/DoQ.
	// Serialise (SetWriteDeadline, WriteTo) on the shared PacketConn:
	// concurrent writers would otherwise clobber each other's
	// deadlines.
	if w.writeMu != nil {
		w.writeMu.Lock()
		defer w.writeMu.Unlock()
	}
	if w.writeTimeout > 0 {
		_ = w.pc.SetWriteDeadline(time.Now().Add(w.writeTimeout))
		defer func() { _ = w.pc.SetWriteDeadline(time.Time{}) }()
	}
	_, err = w.pc.WriteTo(out, udst)
	return err
}
