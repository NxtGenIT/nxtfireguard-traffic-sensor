package traffic

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/config"
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

func MonitorAllInterfaces(ctx context.Context, cfg *config.Config, whitelistManager *whitelist.WhitelistManager, evaluationFunc types.EvaluationFunc, wg *sync.WaitGroup) error {
	defer wg.Done()

	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		zap.L().Error("Failed to find network interfaces", zap.Error(err))
		return err
	}

	zap.L().Info("Starting interface monitoring", zap.Int("count", len(interfaces)))

	var innerWG sync.WaitGroup

	for _, iface := range interfaces {
		// Skip inactive, docker, or loopback interfaces
		if len(iface.Addresses) == 0 || isDockerInterface(iface.Name) || isLoopback(iface.Name) {
			zap.L().Debug("Skipping interface", zap.String("interface", iface.Name))
			continue
		}

		innerWG.Add(1)
		go func(i pcap.Interface) {
			defer innerWG.Done()

			err := monitorInterface(ctx, cfg, i.Name, whitelistManager, evaluationFunc)
			if err != nil {
				zap.L().Error("Error monitoring interface",
					zap.String("interface", i.Name),
					zap.Error(err))
			}
		}(iface)
	}

	// Wait for either context cancel or all workers to finish
	done := make(chan struct{})
	go func() {
		innerWG.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		zap.L().Info("Stopping interface monitoring (context canceled)")
	case <-done:
		zap.L().Info("All interface monitors exited")
	}

	return nil
}
func monitorInterface(ctx context.Context, cfg *config.Config, ifaceName string, whitelistManager *whitelist.WhitelistManager, evaluationFunc types.EvaluationFunc) error {
	zap.L().Info("Monitoring interface", zap.String("interface", ifaceName))

	handle, err := pcap.OpenLive(ifaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		zap.L().Error("Failed to open interface", zap.String("interface", ifaceName), zap.Error(err))
		return err
	}
	defer func() {
		handle.Close()
		zap.L().Info("Stopped monitoring interface", zap.String("interface", ifaceName))
	}()

	// Connection tracker
	// TCP: 2 minutes (primarily rely on SYN flags)
	// UDP: 30 seconds (no SYN flag, rely on timeout)
	// Default: 1 minute
	connTracker := NewConnectionTracker(2 * time.Minute)
	connTracker.Start(ctx)
	defer connTracker.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	packetsProcessed := 0
	packetsSkipped := 0
	statsTimer := time.NewTicker(30 * time.Second)
	defer statsTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			// Graceful shutdown on cancel signal
			zap.L().Info("Context canceled — stopping interface monitor",
				zap.String("interface", ifaceName),
				zap.Int("processed", packetsProcessed),
				zap.Int("skipped", packetsSkipped))
			return nil

		case <-statsTimer.C:
			total, ttl := connTracker.GetStats()
			zap.L().Debug("Interface stats",
				zap.String("interface", ifaceName),
				zap.Int("processed", packetsProcessed),
				zap.Int("skipped", packetsSkipped),
				zap.Int("tracked_connections", total),
				zap.Duration("ttl", ttl))

		case packet, ok := <-packets:
			if !ok {
				zap.L().Info("Packet source closed", zap.String("interface", ifaceName))
				return nil
			}

			var src, dst string
			var srcPort, dstPort uint16
			var protocol string
			shouldProcess := false

			// Extract IP addresses
			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				src, dst = ip.SrcIP.String(), ip.DstIP.String()
			} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv6)
				src, dst = ip.SrcIP.String(), ip.DstIP.String()
			}

			// Check whitelist first (early exit for whitelisted traffic)
			if !recommender.ShouldProcessPacket(whitelistManager, src, dst) {
				continue
			}

			// Extract ports and determine if we should process
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				srcPort, dstPort = uint16(tcp.SrcPort), uint16(tcp.DstPort)
				protocol = "tcp"

				// For TCP: Only process SYN packets (new connection attempts)
				// SYN flag set, ACK flag not set = initial SYN
				if tcp.SYN && !tcp.ACK {
					shouldProcess = true
					zap.L().Debug("TCP SYN detected",
						zap.String("src", src),
						zap.Uint16("srcPort", srcPort),
						zap.String("dst", dst),
						zap.Uint16("dstPort", dstPort))
				} else {
					// For non-SYN TCP packets, use connection tracker as fallback
					// This handles cases where we might have missed the SYN
					if connTracker.MarkSeen(src, dst, srcPort, dstPort, protocol) {
						shouldProcess = true
						zap.L().Debug("TCP connection tracked (non-SYN fallback)",
							zap.String("src", src),
							zap.Uint16("srcPort", srcPort),
							zap.String("dst", dst),
							zap.Uint16("dstPort", dstPort))
					}
				}
			} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				udp, _ := udpLayer.(*layers.UDP)
				srcPort, dstPort = uint16(udp.SrcPort), uint16(udp.DstPort)
				protocol = "udp"

				// For UDP: Always use connection tracker (no SYN flag)
				if connTracker.MarkSeen(src, dst, srcPort, dstPort, protocol) {
					shouldProcess = true
					zap.L().Debug("UDP connection tracked",
						zap.String("src", src),
						zap.Uint16("srcPort", srcPort),
						zap.String("dst", dst),
						zap.Uint16("dstPort", dstPort))
				}
			} else {
				// Other protocols (ICMP, etc.) - use connection tracker with port 0
				protocol = "other"
				if connTracker.MarkSeen(src, dst, 0, 0, protocol) {
					shouldProcess = true
					zap.L().Debug("Other protocol tracked",
						zap.String("src", src),
						zap.String("dst", dst),
						zap.String("protocol", protocol))
				}
			}

			if !shouldProcess {
				packetsSkipped++
				continue
			}

			packetsProcessed++

			// Process the connection
			go evaluationFunc(cfg, "source", src, dst, types.Source{SourceType: "interface", SourceName: ifaceName})
			go evaluationFunc(cfg, "destination", dst, src, types.Source{SourceType: "interface", SourceName: ifaceName})
		}
	}
}
