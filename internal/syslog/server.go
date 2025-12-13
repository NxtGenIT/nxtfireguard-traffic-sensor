package syslog

import (
	"context"
	"net"
	"sync"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/config"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/recommender"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/types"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/whitelist"
	"go.uber.org/zap"
	"gopkg.in/mcuadros/go-syslog.v2"
)

func StartSyslogServer(ctx context.Context, cfg *config.Config, whitelistManager *whitelist.WhitelistManager, evaluationFunc types.EvaluationFunc, wg *sync.WaitGroup) {
	defer wg.Done()

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

	// Goroutine to handle log messages
	go func(channel syslog.LogPartsChannel) {
		for {
			select {
			case <-ctx.Done():
				zap.L().Info("Syslog server stopping: context canceled")
				return
			case logParts, ok := <-channel:
				if !ok {
					return
				}
				zap.L().Debug("Received syslog message",
					zap.Any("logParts", logParts),
				)
				src, dst, _ := inferSrcDst(logParts)

				// Early exit if no valid IPs were extracted
				// Empty strings mean either no IPs found or IPs were filtered as invalid
				if src == "" || dst == "" {
					zap.L().Debug("Skipping message: no valid source/destination",
						zap.String("src", src),
						zap.String("dst", dst),
					)
					continue
				}

				if !recommender.ShouldProcessPacket(whitelistManager, src, dst) {
					zap.L().Debug("Skipping message: filtered by whitelist",
						zap.String("src", src),
						zap.String("dst", dst),
					)
					continue
				}

				sourceAddr := "unknown"
				if client, ok := logParts["client"]; ok {
					if addr, ok := client.(net.Addr); ok {
						sourceAddr = addr.String()
						if host, _, err := net.SplitHostPort(sourceAddr); err == nil {
							sourceAddr = host
						}
					}
				}

				go evaluationFunc(cfg, "source", src, dst, types.Source{SourceType: "syslog", SourceName: sourceAddr})
				go evaluationFunc(cfg, "destination", dst, src, types.Source{SourceType: "syslog", SourceName: sourceAddr})
			}
		}
	}(channel)

	// Wait for stop signal
	go func() {
		<-ctx.Done()
		zap.L().Info("Shutting down syslog server")
		server.Kill()
	}()

	server.Wait()
	zap.L().Info("Syslog server exited cleanly")
}
