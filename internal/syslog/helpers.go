package syslog

import (
	"net"
	"regexp"

	"go.uber.org/zap"
)

func extractCEFSrcDst(msg string) (src, dst string) {
	// Match src=IP and dst=IP
	srcRe := regexp.MustCompile(`src=(\d+\.\d+\.\d+\.\d+)`)
	dstRe := regexp.MustCompile(`dst=(\d+\.\d+\.\d+\.\d+)`)
	srcMatch := srcRe.FindStringSubmatch(msg)
	dstMatch := dstRe.FindStringSubmatch(msg)
	if len(srcMatch) > 1 && len(dstMatch) > 1 {
		zap.L().Debug("Extracted CEF source and destination",
			zap.String("src", srcMatch[1]),
			zap.String("dst", dstMatch[1]),
			zap.String("msg", msg),
		)
		return srcMatch[1], dstMatch[1]
	}
	zap.L().Debug("No CEF source/destination found in message",
		zap.String("msg", msg),
	)
	return "", ""
}

func extractCiscoIosSrcDst(msg string) (src, dst string) {
	// Match IP -> IP
	ciscoRe := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\(\d+\)\s*->\s*(\d+\.\d+\.\d+\.\d+)\(\d+\)`)
	match := ciscoRe.FindStringSubmatch(msg)
	if len(match) > 2 {
		zap.L().Debug("Extracted Cisco source and destination",
			zap.String("src", match[1]),
			zap.String("dst", match[2]),
			zap.String("msg", msg),
		)
		return match[1], match[2]
	}
	zap.L().Debug("No Cisco source/destination found in message",
		zap.String("msg", msg),
	)
	return "", ""
}

func extractIPs(msg string) []string {
	ipRegex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	potentialIPs := ipRegex.FindAllString(msg, -1)
	var validIPs []string
	for _, ipStr := range potentialIPs {
		if net.ParseIP(ipStr) != nil {
			validIPs = append(validIPs, ipStr)
		}
	}
	zap.L().Debug("Extracted IPs from message",
		zap.Strings("ips", validIPs),
		zap.String("msg", msg),
	)
	return validIPs
}

// returns true if the IP is invalid, unspecified, or in reserved space.
func isReservedOrInvalidIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	if ip.IsUnspecified() || ip.Equal(net.IPv4(0, 0, 0, 0)) || ip.Equal(net.IPv4(255, 255, 255, 255)) {
		return true
	}
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return true
	}
	return false
}

// returns valid src and dst, or empty strings if invalid.
func validateSrcDst(src, dst string) (string, string) {
	if src == "" || dst == "" || src == dst {
		return "", ""
	}
	if isReservedOrInvalidIP(src) || isReservedOrInvalidIP(dst) {
		return "", ""
	}
	return src, dst
}

// Helper to get logParts keys for logging
func logPartsKeys(logParts map[string]interface{}) []string {
	keys := make([]string, 0, len(logParts))
	for k := range logParts {
		keys = append(keys, k)
	}
	return keys
}
