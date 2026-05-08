package mdns

import (
	"net"
	"time"
)

// BrowseOption configures Browse.
type BrowseOption interface {
	applyBrowse(*browseConfig)
}

type browseOptionFunc func(*browseConfig)

func (f browseOptionFunc) applyBrowse(c *browseConfig) { f(c) }

type browseConfig struct {
	openConn func() (net.PacketConn, error)
}

// WithBrowseConn injects the function used to open the listening
// socket. The default opens the IPv4 mDNS multicast group on udp4. Tests
// pass an in-process [net.PacketConn] factory to avoid binding the real
// multicast group.
func WithBrowseConn(open func() (net.PacketConn, error)) BrowseOption {
	return browseOptionFunc(func(c *browseConfig) { c.openConn = open })
}

// AnnouncerOption configures NewAnnouncer.
type AnnouncerOption interface {
	applyAnnouncer(*announcerConfig)
}

type announcerOptionFunc func(*announcerConfig)

func (f announcerOptionFunc) applyAnnouncer(c *announcerConfig) { f(c) }

type announcerConfig struct {
	transport     Transport
	probeWait     time.Duration // RFC 6762 §8.1: 250ms between probes
	probeCount    int           // RFC 6762 §8.1: 3 probes
	announceWait  time.Duration // RFC 6762 §8.3: 1s between announcements
	announceCount int           // RFC 6762 §8.3: 2 announcements
	now           func() time.Time
}

// WithAnnouncerTransport sets the transport. Required.
func WithAnnouncerTransport(t Transport) AnnouncerOption {
	return announcerOptionFunc(func(c *announcerConfig) { c.transport = t })
}

// WithProbeTiming overrides the probe wait + count.
func WithProbeTiming(wait time.Duration, count int) AnnouncerOption {
	return announcerOptionFunc(func(c *announcerConfig) {
		c.probeWait = wait
		c.probeCount = count
	})
}

// WithAnnounceTiming overrides the announce wait + count.
func WithAnnounceTiming(wait time.Duration, count int) AnnouncerOption {
	return announcerOptionFunc(func(c *announcerConfig) {
		c.announceWait = wait
		c.announceCount = count
	})
}

// WithClock injects a clock for tests.
func WithClock(now func() time.Time) AnnouncerOption {
	return announcerOptionFunc(func(c *announcerConfig) { c.now = now })
}
