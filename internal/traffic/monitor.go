package traffic

import (
	"fmt"
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
		var src, dst string
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			src = ip.SrcIP.String()
			dst = ip.DstIP.String()
		}

		if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv6)
			src = ip.SrcIP.String()
			dst = ip.DstIP.String()
		}

		if src != "" && dst != "" {
			if !recommender.ShouldProcessPacket(whitelistManager, src, dst) {
				continue
			}
			go arbiter.EvaluateAndAct(cfg, src, dst, types.Source{SourceType: "interface", SourceName: ifaceName})
			go arbiter.EvaluateAndAct(cfg, dst, src, types.Source{SourceType: "interface", SourceName: ifaceName})
		}
	}

	return nil
}
