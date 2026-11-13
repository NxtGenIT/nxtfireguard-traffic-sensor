// Package flow is what every traffic source produces: one observed
// connection between two addresses.
package flow

import (
	"net/netip"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/nfg"
)

type Flow struct {
	Src, Dst netip.Addr
	Source   nfg.Source
}

// New normalises both addresses (IPv4-mapped IPv6 becomes IPv4, zones are
// dropped) so the same host always has the same key.
func New(src, dst netip.Addr, source nfg.Source) Flow {
	return Flow{Src: Canonical(src), Dst: Canonical(dst), Source: source}
}

func Canonical(a netip.Addr) netip.Addr { return a.Unmap().WithZone("") }

var metadataIP = netip.AddrFrom4([4]byte{169, 254, 169, 254})

// Scorable reports whether an address can belong to a remote host worth
// scoring. Unspecified, broadcast, loopback, multicast and link-local
// addresses cannot, except the cloud metadata address 169.254.169.254, which
// is a common target of SSRF attempts.
func Scorable(a netip.Addr) bool {
	a = Canonical(a)
	switch {
	case !a.IsValid(), a.IsUnspecified(), a.IsLoopback(), a.IsMulticast():
		return false
	case a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return false
	case a == metadataIP:
		return true
	case a.IsLinkLocalUnicast():
		return false
	}
	return true
}
