package mdns

import (
	"net"
	"time"

	"github.com/lestrrat-go/option/v3"
)

// BrowseOption configures Browse.
type BrowseOption interface {
	option.Interface
	browseOption()
}

type browseOption struct{ option.Interface }

func (browseOption) browseOption() {}

type browseConfig struct {
	openConn func() (net.PacketConn, error)
}

type identBrowseConn struct{}

// WithBrowseConn injects the function used to open the listening
// socket. The default opens the IPv4 mDNS multicast group on udp4. Tests
// pass an in-process [net.PacketConn] factory to avoid binding the real
// multicast group.
func WithBrowseConn(open func() (net.PacketConn, error)) BrowseOption {
	return browseOption{option.New(identBrowseConn{}, open)}
}

// AnnouncerOption configures NewAnnouncer.
type AnnouncerOption interface {
	option.Interface
	announcerOption()
}

type announcerOption struct{ option.Interface }

func (announcerOption) announcerOption() {}

type announcerConfig struct {
	transport     Transport
	probeWait     time.Duration // RFC 6762 §8.1: 250ms between probes
	probeCount    int           // RFC 6762 §8.1: 3 probes
	announceWait  time.Duration // RFC 6762 §8.3: 1s between announcements
	announceCount int           // RFC 6762 §8.3: 2 announcements
	now           func() time.Time
}

// timing carries a (wait, count) pair for probe / announce options.
type timing struct {
	wait  time.Duration
	count int
}

type identAnnouncerTransport struct{}
type identProbeTiming struct{}
type identAnnounceTiming struct{}
type identAnnouncerClock struct{}

// WithAnnouncerTransport sets the transport. Required.
func WithAnnouncerTransport(t Transport) AnnouncerOption {
	return announcerOption{option.New(identAnnouncerTransport{}, t)}
}

// WithProbeTiming overrides the probe wait + count.
func WithProbeTiming(wait time.Duration, count int) AnnouncerOption {
	return announcerOption{option.New(identProbeTiming{}, timing{wait: wait, count: count})}
}

// WithAnnounceTiming overrides the announce wait + count.
func WithAnnounceTiming(wait time.Duration, count int) AnnouncerOption {
	return announcerOption{option.New(identAnnounceTiming{}, timing{wait: wait, count: count})}
}

// WithClock injects a clock for tests.
func WithClock(now func() time.Time) AnnouncerOption {
	return announcerOption{option.New(identAnnouncerClock{}, now)}
}
