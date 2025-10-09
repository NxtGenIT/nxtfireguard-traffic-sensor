package traffic

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/config"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/arbiter"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/recommender"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/types"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/whitelist"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"go.uber.org/zap"
)

func isDockerInterface(name string) bool {
	// Common Docker interface prefixes: docker0, br-*, veth*
	return strings.HasPrefix(name, "docker") ||
		strings.HasPrefix(name, "br-") ||
		strings.HasPrefix(name, "veth")
}

func isLoopback(name string) bool {
	return strings.HasPrefix(name, "loopback") ||
		strings.HasPrefix(name, "lo")
}

func MonitorAllInterfaces(cfg *config.Config, whitelistManager *whitelist.WhitelistManager) error {
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		zap.L().Error("Failed to find network interfaces", zap.Error(err))
		return err
	}

	var wg sync.WaitGroup
	for _, iface := range interfaces {
		// Skip interfaces with no addresses (inactive)
		if len(iface.Addresses) == 0 {
			zap.L().Debug("Skipping inactive interface", zap.String("interface", iface.Name))
			continue
		}
		// Skip Docker-related interfaces
		if isDockerInterface(iface.Name) {
			zap.L().Debug("Skipping Docker interface", zap.String("interface", iface.Name))
			continue
		}
		// Skip loopback
		if isLoopback(iface.Name) {
			zap.L().Debug("Skipping loopback interface", zap.String("interface", iface.Name))
			continue
		}

		wg.Add(1)
		go func(i pcap.Interface) {
			defer wg.Done()
			if err := monitorInterface(cfg, i.Name, whitelistManager); err != nil {
				zap.L().Error("Error monitoring interface", zap.String("interface", i.Name), zap.Error(err))
			}
		}(iface)
	}

	wg.Wait()
	zap.L().Info("Finished monitoring all interfaces")
	return fmt.Errorf("interface monitoring loop exited")
}

func monitorInterface(cfg *config.Config, ifaceName string, whitelistManager *whitelist.WhitelistManager) error {
	zap.L().Info("Monitoring interface", zap.String("interface", ifaceName))

	handle, err := pcap.OpenLive(ifaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		zap.L().Error("Failed to open interface", zap.String("interface", ifaceName), zap.Error(err))
		return err
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		// Ethernet
		var srcMAC, dstMAC, ethType string
		if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
			eth, _ := ethLayer.(*layers.Ethernet)
			srcMAC = eth.SrcMAC.String()
			dstMAC = eth.DstMAC.String()
			ethType = eth.EthernetType.String()
		}

		// ARP
		var arpSrcIP, arpDstIP, arpSrcMAC, arpDstMAC, arpOp string
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp, _ := arpLayer.(*layers.ARP)
			arpSrcIP = net.IP(arp.SourceProtAddress).String()
			arpDstIP = net.IP(arp.DstProtAddress).String()
			arpSrcMAC = net.HardwareAddr(arp.SourceHwAddress).String()
			arpDstMAC = net.HardwareAddr(arp.DstHwAddress).String()
			arpOp = fmt.Sprintf("%d", arp.Operation)
		}

		// IPv4
		var src, dst string
		var version, ihl, tos, ttl *uint8
		var length, id, fragOffset *uint16
		var flags, protocol, options, padding *string
		var checksum *uint16
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			src = ip.SrcIP.String()
			dst = ip.DstIP.String()
			version = &ip.Version
			ihl = &ip.IHL
			tos = &ip.TOS
			length = &ip.Length
			id = &ip.Id
			flags = strPtr(ip.Flags.String())
			fragOffset = &ip.FragOffset
			ttl = &ip.TTL
			protocol = strPtr(ip.Protocol.String())
			checksum = &ip.Checksum
			options = strPtr(fmt.Sprintf("%v", ip.Options))
			padding = strPtr(fmt.Sprintf("%v", ip.Padding))
		}

		// IPv6
		var flowLabel *uint32
		if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
			ip6, _ := ip6Layer.(*layers.IPv6)
			src = ip6.SrcIP.String()
			dst = ip6.DstIP.String()
			version = &ip6.Version
			flowLabel = &ip6.FlowLabel
			ttl = &ip6.HopLimit
			protocol = strPtr(ip6.NextHeader.String())
		}

		// TCP
		var srcPort, dstPort *uint16
		var tcpSeq, tcpAck *uint32
		var tcpFlags *string
		var tcpWindow *uint16
		var tcpOffset *uint8
		var tcpOptions *string
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			s, d := uint16(tcp.SrcPort), uint16(tcp.DstPort)
			srcPort, dstPort = &s, &d
			seq, ack := uint32(tcp.Seq), uint32(tcp.Ack)
			tcpSeq, tcpAck = &seq, &ack
			w := uint16(tcp.Window)
			tcpWindow = &w
			o := uint8(tcp.DataOffset)
			tcpOffset = &o
			tcpOptions = strPtr(fmt.Sprintf("%v", tcp.Options))
		}

		// UDP
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			s, d := uint16(udp.SrcPort), uint16(udp.DstPort)
			srcPort, dstPort = &s, &d
		}

		// ICMP
		var icmpType, icmpCode *uint8
		var icmpChecksum, icmpId, icmpSeq *uint16
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			t, c := uint8(icmp.TypeCode.Type()), uint8(icmp.TypeCode.Code())
			icmpType, icmpCode = &t, &c
			icmpChecksum = &icmp.Checksum
			// For echo requests/replies, extract ID/Seq from payload
			if len(icmp.Payload) >= 4 {
				id := binary.BigEndian.Uint16(icmp.Payload[0:2])
				seq := binary.BigEndian.Uint16(icmp.Payload[2:4])
				icmpId, icmpSeq = &id, &seq
			}
		}

		// DNS
		var dnsID *uint16
		var dnsQR, dnsRR, dnsOpCode, dnsError *string
		var dnsResponse *bool
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dns, _ := dnsLayer.(*layers.DNS)
			id := dns.ID
			dnsID = &id
			qr := fmt.Sprintf("%v", dns.Questions)
			rr := fmt.Sprintf("%v", dns.Answers)
			op := dns.OpCode.String()
			dnsQR, dnsRR, dnsOpCode = &qr, &rr, &op
			resp := dns.QR
			dnsResponse = &resp
			if dns.ResponseCode != 0 {
				errStr := dns.ResponseCode.String()
				dnsError = &errStr
			}
		}

		// Packet for pcap
		ci := packet.Metadata().CaptureInfo
		rawData := packet.Data()
		encodedRaw := base64.StdEncoding.EncodeToString(rawData)
		var buf bytes.Buffer
		w := pcapgo.NewWriter(&buf)
		_ = w.WriteFileHeader(1600, layers.LinkTypeEthernet)
		_ = w.WritePacket(ci, rawData)
		encodedPcap := base64.StdEncoding.EncodeToString(buf.Bytes())

		info := types.PacketInfo{
			SrcMAC:            srcMAC,
			DstMAC:            dstMAC,
			EthernetType:      ethType,
			ARPSourceIP:       arpSrcIP,
			ARPDestIP:         arpDstIP,
			ARPSourceMAC:      arpSrcMAC,
			ARPDestMAC:        arpDstMAC,
			ARPOperation:      arpOp,
			Src:               src,
			Dst:               dst,
			Version:           version,
			IHL:               ihl,
			TOS:               tos,
			Length:            length,
			ID:                id,
			Flags:             flags,
			FragOffset:        fragOffset,
			TTL:               ttl,
			Protocol:          protocol,
			Checksum:          checksum,
			Options:           options,
			Padding:           padding,
			FlowLabel:         flowLabel,
			SrcPort:           srcPort,
			DstPort:           dstPort,
			TCPSeq:            tcpSeq,
			TCPAck:            tcpAck,
			TCPFlags:          tcpFlags,
			TCPWindow:         tcpWindow,
			TCPOffset:         tcpOffset,
			TCPOptions:        tcpOptions,
			ICMPType:          icmpType,
			ICMPCode:          icmpCode,
			ICMPChecksum:      icmpChecksum,
			ICMPId:            icmpId,
			ICMPSeq:           icmpSeq,
			DNSID:             dnsID,
			DNSQuery:          dnsQR,
			DNSAnswer:         dnsRR,
			DNSOpCode:         dnsOpCode,
			DNSResponse:       dnsResponse,
			DNSError:          dnsError,
			CaptureSource:     "interface",
			Interface:         &ifaceName,
			PacketBase64:      &encodedPcap,
			PacketRawBase64:   &encodedRaw,
			CaptureTimestamp:  ptrInt64(ci.Timestamp.Unix()),
			CaptureLength:     ptrInt(ci.CaptureLength),
			OrigLength:        ptrInt(ci.Length),
			TrafficSensorName: cfg.SensorName,
		}

		if src != "" && dst != "" {
			if !recommender.ShouldProcessPacket(whitelistManager, src, dst) {
				continue
			}
			go arbiter.EvaluateAndAct(cfg, src, types.Source{SourceType: "interface", SourceName: ifaceName})
			go arbiter.EvaluateAndAct(cfg, dst, types.Source{SourceType: "interface", SourceName: ifaceName})
		}

		log.Printf("info: %+v", info)
	}

	return nil
}
