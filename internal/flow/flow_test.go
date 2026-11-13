package flow

import (
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/nfg"
	"net/netip"
	"testing"
)

func TestScorable(t *testing.T) {
	for ip, want := range map[string]bool{
		"203.0.113.1":     true,
		"10.0.0.1":        true,
		"169.254.169.254": true,
		"::ffff:1.2.3.4":  true,
		"2001:db8::1":     true,
		"0.0.0.0":         false,
		"::":              false,
		"255.255.255.255": false,
		"127.0.0.1":       false,
		"::1":             false,
		"224.0.0.1":       false,
		"ff02::1":         false,
		"169.254.1.1":     false,
		"fe80::1":         false,
	} {
		if got := Scorable(netip.MustParseAddr(ip)); got != want {
			t.Errorf("Scorable(%s) = %v", ip, got)
		}
	}
	if Scorable(netip.Addr{}) {
		t.Error("zero Addr must not be scorable")
	}
}

func TestNewCanonicalises(t *testing.T) {
	f := New(netip.MustParseAddr("::ffff:1.2.3.4"), netip.MustParseAddr("fe80::1%eth0"), nfg.Source{})
	if f.Src.String() != "1.2.3.4" || f.Dst.String() != "fe80::1" {
		t.Errorf("got %v %v", f.Src, f.Dst)
	}
}
