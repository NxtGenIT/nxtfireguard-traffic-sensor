package policy

import (
	"net/netip"
	"testing"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/nfg"
)

func ready(t *testing.T) *State {
	t.Helper()
	var s State
	s.SetAlertThreshold(50)
	s.SetBlocklists([]nfg.Blocklist{
		{Name: "public-only", ShouldIncludePublicIPs: true, NfgScoreThresholdPublicIPs: 60},
		{Name: "both", ShouldIncludePublicIPs: true, ShouldIncludePrivateIPs: true, NfgScoreThresholdPublicIPs: 80, NfgScoreThresholdPrivateIPs: 20},
	})
	s.SetWhitelist([]string{"192.0.2.0/24", "2001:db8:1::/48", "198.51.100.7"})
	return &s
}

func TestStateNilUntilComplete(t *testing.T) {
	var s State
	s.SetAlertThreshold(1)
	s.SetWhitelist(nil)
	if s.Load() != nil {
		t.Fatal("policy without blocklists must not be published")
	}
	s.SetBlocklists(nil)
	if s.Load() == nil {
		t.Fatal("policy with all parts (even empty) must be published")
	}
}

func TestDecide(t *testing.T) {
	p := ready(t).Load()
	cases := []struct {
		ip        string
		score     int32
		alert     bool
		blocklist []string
	}{
		{"203.0.113.1", 49, false, nil},
		{"203.0.113.1", 50, true, nil},
		{"203.0.113.1", 60, true, []string{"public-only"}},
		{"203.0.113.1", 80, true, []string{"public-only", "both"}},
		{"10.1.2.3", 20, false, []string{"both"}},
		{"10.1.2.3", 90, true, []string{"both"}},
		{"fd00::1", 25, false, []string{"both"}},
	}
	for _, c := range cases {
		alert, blocks := p.Decide(netip.MustParseAddr(c.ip), c.score)
		var names []string
		for _, b := range blocks {
			if !b.Block {
				t.Errorf("%s: non-blocking decision returned", c.ip)
			}
			names = append(names, b.Blocklist)
		}
		if alert != c.alert || len(names) != len(c.blocklist) {
			t.Errorf("Decide(%s, %d) = %v %v, want %v %v", c.ip, c.score, alert, names, c.alert, c.blocklist)
			continue
		}
		for i := range names {
			if names[i] != c.blocklist[i] {
				t.Errorf("Decide(%s, %d) blocklists %v, want %v", c.ip, c.score, names, c.blocklist)
			}
		}
	}
	_, blocks := p.Decide(netip.MustParseAddr("203.0.113.1"), 80)
	if blocks[0].Reason != "Score 80 >= threshold 60" {
		t.Errorf("reason %q", blocks[0].Reason)
	}
}

func TestWhitelist(t *testing.T) {
	s := ready(t)
	if bad := s.SetWhitelist([]string{"192.0.2.0/24", "2001:db8:1::/48", "198.51.100.7", "::ffff:203.0.113.0/120", "not-a-cidr"}); len(bad) != 1 || bad[0] != "not-a-cidr" {
		t.Fatalf("invalid entries = %v", bad)
	}
	p := s.Load()
	for ip, want := range map[string]bool{
		"192.0.2.200":     true,
		"192.0.3.1":       false,
		"2001:db8:1:ff::": true,
		"2001:db8:2::":    false,
		"198.51.100.7":    true,
		"198.51.100.8":    false,
		"203.0.113.9":     true,
	} {
		if got := p.Whitelisted(netip.MustParseAddr(ip)); got != want {
			t.Errorf("Whitelisted(%s) = %v", ip, got)
		}
	}
}

func TestSetBlocklistsReportsChange(t *testing.T) {
	var s State
	l := []nfg.Blocklist{{ID: 1, Name: "a"}}
	if !s.SetBlocklists(l) {
		t.Error("first set must count as a change")
	}
	if s.SetBlocklists([]nfg.Blocklist{{ID: 1, Name: "a"}}) {
		t.Error("equal lists must not count as a change")
	}
	if !s.SetBlocklists([]nfg.Blocklist{{ID: 1, Name: "a", ShouldIncludePublicIPs: true}}) {
		t.Error("changed list must count as a change")
	}
}
