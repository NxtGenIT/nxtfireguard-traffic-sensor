// Package capture sniffs the host's network interfaces and reports each new
// connection once.
package capture

import (
	"net/netip"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// trackTTL is how long a connection counts as seen after its last packet.
const trackTTL = 2 * time.Minute

// maxTracked bounds the connection table (about 100 bytes per entry), so a
// flood of spoofed sources or a port scan cannot exhaust memory. When it is
// full, the table starts over: some connections are then evaluated twice.
var maxTracked = 1 << 19

// Classifier decides which packets start a connection worth evaluating.
// A TCP SYN without ACK always does. Any other packet does if its
// connection (in either direction) was not seen within trackTTL, which
// covers UDP, ICMP and TCP connections whose SYN was missed. A Classifier
// is used by one goroutine.
type Classifier struct {
	seen      map[connKey]time.Time
	lastSweep time.Time
	now       func() time.Time
}

type connKey struct {
	proto          uint8
	loIP, hiIP     netip.Addr
	loPort, hiPort uint16
}

func NewClassifier() *Classifier {
	return &Classifier{seen: map[connKey]time.Time{}, now: time.Now}
}

// Classify returns the packet's addresses if it starts a new connection.
func (c *Classifier) Classify(p gopacket.Packet) (src, dst netip.Addr, isNew bool) {
	var proto uint8
	switch ip := p.NetworkLayer().(type) {
	case *layers.IPv4:
		src, _ = netip.AddrFromSlice(ip.SrcIP)
		dst, _ = netip.AddrFromSlice(ip.DstIP)
		proto = uint8(ip.Protocol)
	case *layers.IPv6:
		src, _ = netip.AddrFromSlice(ip.SrcIP)
		dst, _ = netip.AddrFromSlice(ip.DstIP)
		proto = uint8(ip.NextHeader)
	default:
		return src, dst, false
	}

	var sport, dport uint16
	switch t := p.TransportLayer().(type) {
	case *layers.TCP:
		if t.SYN && !t.ACK {
			return src, dst, true
		}
		sport, dport = uint16(t.SrcPort), uint16(t.DstPort)
	case *layers.UDP:
		sport, dport = uint16(t.SrcPort), uint16(t.DstPort)
	}
	return src, dst, c.markSeen(proto, src, dst, sport, dport)
}

func (c *Classifier) markSeen(proto uint8, a, b netip.Addr, pa, pb uint16) bool {
	if b.Less(a) || (a == b && pb < pa) {
		a, b, pa, pb = b, a, pb, pa
	}
	k := connKey{proto: proto, loIP: a, hiIP: b, loPort: pa, hiPort: pb}
	now := c.now()
	if now.Sub(c.lastSweep) > trackTTL/2 {
		for key, t := range c.seen {
			if now.Sub(t) > trackTTL {
				delete(c.seen, key)
			}
		}
		c.lastSweep = now
	}
	last, ok := c.seen[k]
	if !ok && len(c.seen) >= maxTracked {
		clear(c.seen)
		c.lastSweep = now
	}
	c.seen[k] = now
	return !ok || now.Sub(last) > trackTTL
}
