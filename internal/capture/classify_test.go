package capture

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type pkt struct {
	src, dst         string
	sport, dport     uint16
	proto            string // tcp, udp, icmp
	syn, ack, isIPv6 bool
}

func build(t *testing.T, p pkt) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}}
	var ls []gopacket.SerializableLayer
	var netLayer gopacket.NetworkLayer
	ipProto := map[string]layers.IPProtocol{"tcp": layers.IPProtocolTCP, "udp": layers.IPProtocolUDP, "icmp": layers.IPProtocolICMPv4}[p.proto]
	if p.isIPv6 {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: ipProto, SrcIP: net.ParseIP(p.src), DstIP: net.ParseIP(p.dst)}
		ls, netLayer = append(ls, eth, ip), ip
	} else {
		eth.EthernetType = layers.EthernetTypeIPv4
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: ipProto, SrcIP: net.ParseIP(p.src).To4(), DstIP: net.ParseIP(p.dst).To4()}
		ls, netLayer = append(ls, eth, ip), ip
	}
	switch p.proto {
	case "tcp":
		tcp := &layers.TCP{SrcPort: layers.TCPPort(p.sport), DstPort: layers.TCPPort(p.dport), SYN: p.syn, ACK: p.ack, Window: 1024}
		_ = tcp.SetNetworkLayerForChecksum(netLayer)
		ls = append(ls, tcp)
	case "udp":
		udp := &layers.UDP{SrcPort: layers.UDPPort(p.sport), DstPort: layers.UDPPort(p.dport)}
		_ = udp.SetNetworkLayerForChecksum(netLayer)
		ls = append(ls, udp)
	case "icmp":
		ls = append(ls, &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(8, 0)})
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ls...); err != nil {
		t.Fatal(err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true})
}

func TestClassify(t *testing.T) {
	now := time.Unix(0, 0)
	c := NewClassifier()
	c.now = func() time.Time { return now }
	steps := []struct {
		name    string
		p       pkt
		advance time.Duration
		want    bool
	}{
		{"syn is always new", pkt{src: "203.0.113.1", dst: "10.0.0.1", sport: 1000, dport: 22, proto: "tcp", syn: true}, 0, true},
		{"syn again is new again", pkt{src: "203.0.113.1", dst: "10.0.0.1", sport: 1000, dport: 22, proto: "tcp", syn: true}, 0, true},
		{"syn-ack is tracked like any packet", pkt{src: "10.0.0.1", dst: "203.0.113.1", sport: 22, dport: 1000, proto: "tcp", syn: true, ack: true}, 0, true},
		{"reply of the tracked connection", pkt{src: "203.0.113.1", dst: "10.0.0.1", sport: 1000, dport: 22, proto: "tcp", ack: true}, 0, false},
		{"mid-stream tcp without syn", pkt{src: "198.51.100.1", dst: "10.0.0.1", sport: 2000, dport: 443, proto: "tcp", ack: true}, 0, true},
		{"udp first packet", pkt{src: "10.0.0.1", dst: "198.51.100.53", sport: 5353, dport: 53, proto: "udp"}, 0, true},
		{"udp reply", pkt{src: "198.51.100.53", dst: "10.0.0.1", sport: 53, dport: 5353, proto: "udp"}, 0, false},
		{"udp other port", pkt{src: "10.0.0.1", dst: "198.51.100.53", sport: 5354, dport: 53, proto: "udp"}, 0, true},
		{"udp after ttl", pkt{src: "10.0.0.1", dst: "198.51.100.53", sport: 5353, dport: 53, proto: "udp"}, trackTTL + time.Second, true},
		{"icmp", pkt{src: "10.0.0.1", dst: "198.51.100.9", proto: "icmp"}, 0, true},
		{"icmp again", pkt{src: "198.51.100.9", dst: "10.0.0.1", proto: "icmp"}, 0, false},
		{"ipv6 syn", pkt{src: "2001:db8::1", dst: "2001:db8::2", sport: 1, dport: 2, proto: "tcp", syn: true, isIPv6: true}, 0, true},
		{"ipv6 udp", pkt{src: "2001:db8::1", dst: "2001:db8::2", sport: 1, dport: 2, proto: "udp", isIPv6: true}, 0, true},
	}
	for _, s := range steps {
		now = now.Add(s.advance)
		src, dst, isNew := c.Classify(build(t, s.p))
		if isNew != s.want {
			t.Errorf("%s: new = %v", s.name, isNew)
		}
		if src.String() != s.p.src || dst.String() != s.p.dst {
			t.Errorf("%s: addrs %v %v", s.name, src, dst)
		}
	}
	if len(c.seen) > 8 {
		t.Errorf("expired entries not swept: %d", len(c.seen))
	}
}

func TestEligible(t *testing.T) {
	for name, want := range map[string]bool{"eth0": true, "ens18": true, "wlan0": true, "lo": false, "lo0": false, "docker0": false, "br-1a2b": false, "veth99": false} {
		if Eligible(name, true) != want {
			t.Errorf("Eligible(%s) = %v", name, !want)
		}
	}
	if Eligible("eth0", false) {
		t.Error("interface without address")
	}
}
