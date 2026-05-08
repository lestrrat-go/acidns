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
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/lestrrat-go/acidns"
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
// server does not re-sign it. resolverSK MUST be the X25519 scalar
// whose public form is cert.ResolverPK; the package cannot verify
// this binding (signed material is opaque) so a mismatch silently
// produces undecryptable responses.
func NewServer(addr netip.AddrPort, h acidns.Handler, cert *Cert, resolverSK [32]byte, opts ...ServerOption) (*Server, error) {
	if h == nil {
		return nil, fmt.Errorf("dnscrypt: handler is nil")
	}
	if cert == nil {
		return nil, fmt.Errorf("dnscrypt: cert is nil")
	}
	if cert.esVersion != ESVersion2 {
		return nil, fmt.Errorf("%w: ES%d (only ES%d is implemented)", ErrUnsupportedESVersion, cert.esVersion, ESVersion2)
	}
	cfg := serverConfig{
		bufferSize:  4096,
		maxInflight: 4096,
	}
	for _, o := range opts {
		o.applyDNSCryptServer(&cfg)
	}
	return &Server{
		addr:       addr,
		handler:    h,
		cert:       cert,
		resolverSK: resolverSK,
		cfg:        cfg,
	}, nil
}

// Run binds a fresh UDP socket and spawns the dispatch goroutine.
// Cancelling ctx is the only way to stop the instance.
func (s *Server) Run(ctx context.Context) (*ServerController, error) {
	now := time.Now()
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
		addr: bound,
		done: make(chan struct{}),
		loop: loop,
	}
	go func() {
		defer close(ctrl.done)
		err := loop.run(ctx)
		if err != nil && !errors.Is(err, ErrServerClosed) {
			ctrl.setErr(err)
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
// than verbosity here.
type ServerController struct {
	addr netip.AddrPort
	done chan struct{}
	err  atomic.Pointer[error]
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
	now := time.Now()
	if now.Before(cert.validFrom) || now.After(cert.validUntil) {
		return fmt.Errorf("%w: now=%s window=[%s, %s]",
			ErrCertExpired, now, cert.validFrom, cert.validUntil)
	}
	c.loop.material.Store(&keyMaterial{cert: cert, resolverSK: resolverSK})
	return nil
}

// Addr returns the bound UDP address.
func (c *ServerController) Addr() netip.AddrPort { return c.addr }

// Done closes when the work goroutine has exited.
func (c *ServerController) Done() <-chan struct{} { return c.done }

// Err returns the terminal error, or nil after a clean shutdown.
func (c *ServerController) Err() error {
	if p := c.err.Load(); p != nil {
		return *p
	}
	return nil
}

// Wait blocks until the server has shut down.
func (c *ServerController) Wait() error {
	<-c.done
	return c.Err()
}

func (c *ServerController) setErr(err error) {
	if err != nil {
		c.err.Store(&err)
	}
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
	if !bytes.Equal(body[0:8], mat.cert.clientMagic[:]) {
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
		pc:          l.pc,
		dst:         src,
		local:       l.addr,
		clientNonce: clientNonce,
		aead:        aead,
	}
	_ = shared // referenced via aead's bound key
	l.handler.ServeDNS(ctx, w, q)
}

// responseWriter implements [acidns.ResponseWriter] over a single
// DNSCrypt v2 datagram exchange. Each WriteMsg call encrypts the
// response and ships it back to the client; subsequent calls are
// rejected because UDP carries one response per query.
type responseWriter struct {
	pc          net.PacketConn
	dst         netip.AddrPort
	local       netip.AddrPort
	clientNonce [12]byte
	aead        cipher.AEAD
	wrote       bool
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
	_, err = w.pc.WriteTo(out, udst)
	return err
}
