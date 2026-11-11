// Package policy decides, from an IP's score and the rules the backend sent,
// whether to alert and which blocklists to recommend the IP for.
package policy

import (
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/nfg"
)

// Policy is an immutable snapshot of the backend rules.
type Policy struct {
	AlertThreshold int32
	Blocklists     []nfg.Blocklist
	whitelist      prefixSet
}

// Whitelisted reports whether ip is in one of the whitelisted CIDRs.
func (p *Policy) Whitelisted(ip netip.Addr) bool { return p.whitelist.contains(ip) }

// Decide returns whether score warrants an alert and the blocklists it
// should be recommended for. Private and public addresses have separate
// switches and thresholds per blocklist.
func (p *Policy) Decide(ip netip.Addr, score int32) (alert bool, blocks []nfg.Decision) {
	private := ip.IsPrivate()
	for _, bl := range p.Blocklists {
		include, threshold := bl.ShouldIncludePublicIPs, bl.NfgScoreThresholdPublicIPs
		if private {
			include, threshold = bl.ShouldIncludePrivateIPs, bl.NfgScoreThresholdPrivateIPs
		}
		if include && score >= threshold {
			blocks = append(blocks, nfg.Decision{
				Block:     true,
				Reason:    fmt.Sprintf("Score %d >= threshold %d", score, threshold),
				Blocklist: bl.Name,
			})
		}
	}
	return score >= p.AlertThreshold, blocks
}

// State assembles a Policy from the three parts the backend sends
// separately. Readers get the latest complete snapshot without locking.
type State struct {
	mu        sync.Mutex
	threshold *int32
	lists     []nfg.Blocklist
	white     *prefixSet
	cur       atomic.Pointer[Policy]
}

// Load returns the current policy, or nil until every part has been set.
func (s *State) Load() *Policy { return s.cur.Load() }

func (s *State) SetAlertThreshold(t int32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.threshold = &t
	s.publish()
}

// SetBlocklists reports whether the blocklists differ from the previous ones.
func (s *State) SetBlocklists(lists []nfg.Blocklist) (changed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed = s.lists == nil || !reflect.DeepEqual(s.lists, lists)
	s.lists = slices.Clone(lists)
	if s.lists == nil {
		s.lists = []nfg.Blocklist{}
	}
	s.publish()
	return changed
}

// SetWhitelist returns the entries that are not valid CIDRs; they are skipped.
func (s *State) SetWhitelist(cidrs []string) (invalid []string) {
	set, invalid := newPrefixSet(cidrs)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.white = &set
	s.publish()
	return invalid
}

func (s *State) publish() {
	if s.threshold == nil || s.lists == nil || s.white == nil {
		return
	}
	s.cur.Store(&Policy{AlertThreshold: *s.threshold, Blocklists: s.lists, whitelist: *s.white})
}

// prefixSet answers "is this address inside any of these prefixes" with one
// map lookup per distinct prefix length.
type prefixSet struct {
	set     map[netip.Prefix]struct{}
	lengths [2][]int // IPv4, IPv6
}

func newPrefixSet(cidrs []string) (prefixSet, []string) {
	ps := prefixSet{set: map[netip.Prefix]struct{}{}}
	var invalid []string
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			a, aerr := netip.ParseAddr(c)
			if aerr != nil {
				invalid = append(invalid, c)
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if bits := p.Bits(); p.Addr().Is4In6() {
			// ::ffff:a.b.c.d/n covers the IPv4 prefix a.b.c.d/(n-96).
			if bits < 96 {
				invalid = append(invalid, c)
				continue
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), bits-96)
		}
		p = p.Masked()
		fam := family(p.Addr())
		if !slices.Contains(ps.lengths[fam], p.Bits()) {
			ps.lengths[fam] = append(ps.lengths[fam], p.Bits())
		}
		ps.set[p] = struct{}{}
	}
	return ps, invalid
}

func (ps prefixSet) contains(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, bits := range ps.lengths[family(ip)] {
		p, err := ip.Prefix(bits)
		if err == nil {
			if _, ok := ps.set[p]; ok {
				return true
			}
		}
	}
	return false
}

func family(a netip.Addr) int {
	if a.Is4() {
		return 0
	}
	return 1
}
