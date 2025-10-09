package recommender

import (
	"fmt"
	"net"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/blocklist"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/sqlite"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/types"
	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/whitelist"
	"go.uber.org/zap"
)

func privateIpCheck(ip string) (bool, error) {
	addr := net.ParseIP(ip)
	if addr == nil {
		zap.L().Warn("Invalid IP address",
			zap.String("ip", ip),
		)
		return false, fmt.Errorf("not a valid IP address: %s", ip)
	}
	isPrivate := addr.IsPrivate()
	zap.L().Debug("IP address type checked",
		zap.String("ip", ip),
		zap.Bool("isPrivate", isPrivate),
	)
	return isPrivate, nil
}

func ShouldProcessPacket(wm *whitelist.WhitelistManager, src, dst string) bool {
	// If either IP is whitelisted, skip processing
	if wm.IsWhitelisted(src) {
		zap.L().Debug("Source IP is whitelisted, skipping", zap.String("src", src))
		return false
	}
	if wm.IsWhitelisted(dst) {
		zap.L().Debug("Destination IP is whitelisted, skipping", zap.String("dst", dst))
		return false
	}
	return true
}

func ShouldBlock(ip string) ([]types.Decision, int32) {
	var decisions []types.Decision

	zap.L().Debug("Checking if IP should be blocked",
		zap.String("ip", ip),
	)

	score, err := sqlite.Lookup(ip)
	if err != nil {
		zap.L().Error("Failed to retrieve score for IP",
			zap.String("ip", ip),
			zap.Error(err),
		)
		decisions = append(decisions, types.Decision{
			Block:     false,
			Reason:    fmt.Sprintf("Error retrieving score: %v", err),
			Blocklist: "N/A",
		})
		return decisions, *score
	}

	isPrivate, err := privateIpCheck(ip)
	if err != nil {
		zap.L().Error("IP validation failed",
			zap.String("ip", ip),
			zap.Error(err),
		)
		decisions = append(decisions, types.Decision{
			Block:     false,
			Reason:    fmt.Sprintf("IP validation failed: %v", err),
			Blocklist: "N/A",
		})
		return decisions, *score
	}

	blocklists := blocklist.GetBlocklists()
	zap.L().Debug("Retrieved blocklists for decision",
		zap.Int("blocklistCount", len(blocklists)),
		zap.String("ip", ip),
	)

	for _, bl := range blocklists {
		if isPrivate && !bl.ShouldIncludePrivateIPs {
			zap.L().Debug("Skipping blocklist for private IP",
				zap.String("blocklist", bl.Name),
				zap.String("ip", ip),
			)
			continue
		}
		if !isPrivate && !bl.ShouldIncludePublicIPs {
			zap.L().Debug("Skipping blocklist for public IP",
				zap.String("blocklist", bl.Name),
				zap.String("ip", ip),
			)
			continue
		}

		threshold := bl.NfgScoreThresholdPublicIPs
		if isPrivate {
			threshold = bl.NfgScoreThresholdPrivateIPs
		}

		if *score >= threshold {
			zap.L().Debug("IP meets blocklist threshold",
				zap.String("ip", ip),
				zap.String("blocklist", bl.Name),
				zap.Int32("score", *score),
				zap.Int32("threshold", threshold),
			)
			decisions = append(decisions, types.Decision{
				Block:     true,
				Reason:    fmt.Sprintf("Score %v >= threshold %d", *score, threshold),
				Blocklist: bl.Name,
			})
		}
	}

	if len(decisions) == 0 {
		zap.L().Debug("IP did not meet any blocklist threshold",
			zap.String("ip", ip),
			zap.Int32("score", *score),
		)
		decisions = append(decisions, types.Decision{
			Block:     false,
			Reason:    fmt.Sprintf("Score %v did not meet any blocklist threshold", *score),
			Blocklist: "None",
		})
	}

	zap.L().Debug("Decision for IP",
		zap.String("ip", ip),
		zap.Any("decisions", decisions),
	)
	return decisions, *score
}
