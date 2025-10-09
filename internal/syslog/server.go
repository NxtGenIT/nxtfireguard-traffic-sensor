package syslog

import (
	"log"
	"net"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/config"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/arbiter"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/recommender"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/types"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/whitelist"
	"go.uber.org/zap"
	"gopkg.in/mcuadros/go-syslog.v2"
)

func StartSyslogServer(cfg *config.Config, whitelistManager *whitelist.WhitelistManager) {
	zap.L().Info("Starting Syslog Server",
		zap.String("protocol", "udp"),
		zap.String("address", "0.0.0.0:514"),
	)
	zap.L().Info("Starting Syslog Server",
		zap.String("protocol", "tcp"),
		zap.String("address", "0.0.0.0:514"),
	)

	channel := make(syslog.LogPartsChannel)
	handler := syslog.NewChannelHandler(channel)

	server := syslog.NewServer()
	server.SetFormat(syslog.Automatic)
	server.SetHandler(handler)
	server.ListenUDP("0.0.0.0:514")
	server.ListenTCP("0.0.0.0:514")
	server.Boot()

	go func(channel syslog.LogPartsChannel) {
		for logParts := range channel {
			zap.L().Debug("Received syslog message",
				zap.Any("logParts", logParts),
			)
			src, dst, msg := inferSrcDst(logParts)
			if !recommender.ShouldProcessPacket(whitelistManager, src, dst) {
				continue
			}

			// Extract sender address from logParts["client"]
			sourceAddr := "unknown"
			if client, ok := logParts["client"]; ok {
				if addr, ok := client.(net.Addr); ok {
					sourceAddr = addr.String() // includes port
					if host, _, err := net.SplitHostPort(sourceAddr); err == nil {
						sourceAddr = host
					}
				}
			}

			go arbiter.EvaluateAndAct(cfg, src, types.Source{SourceType: "syslog", SourceName: sourceAddr})
			go arbiter.EvaluateAndAct(cfg, dst, types.Source{SourceType: "syslog", SourceName: sourceAddr})

			info := types.PacketInfo{
				Src:               src,
				Dst:               dst,
				CaptureSource:     "syslog",
				TrafficSensorName: cfg.SensorName,
				RawSyslogMessage:  &msg,
			}

			log.Print("info: %+v", info)
		}
	}(channel)

	server.Wait()
}
