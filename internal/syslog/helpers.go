package syslog

import (
	"encoding/json"
	"net"
	"regexp"
	"strings"

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

// extractPfSenseSrcDst parses pfSense/OPNsense filterlog CSV format
// Format: rule,sub-rule,anchor,tracker,interface,reason,action,dir,ipversion,...,srcip,dstip,...
// Source IP is typically at index 17 (IPv4) or 18 (IPv6)
// Destination IP is typically at index 18 (IPv4) or 19 (IPv6)
func extractPfSenseSrcDst(msg string) (src, dst string) {
	fields := strings.Split(msg, ",")

	// pfSense filterlog format has IPs at different positions depending on IP version
	if len(fields) < 19 {
		return "", ""
	}

	if len(fields) >= 9 {
		src = strings.TrimSpace(fields[18])
		dst = strings.TrimSpace(fields[19])
	}

	return src, dst
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
	if ip.IsLoopback() || ip.IsMulticast() {
		return true
	}

	// Allow AWS metadata IP (169.254.169.254)
	if ip.Equal(net.IPv4(169, 254, 169, 254)) {
		return false
	}

	// Block other link-local addresses
	if ip.IsLinkLocalUnicast() {
		return true
	}

	return false
}

// returns valid src and dst, or empty strings if invalid.
func validateSrcDst(src, dst string) (validSrc, validDst string, srcInvalid, dstInvalid bool) {
	if src == "" || dst == "" {
		return "", "", src == "", dst == ""
	}

	if src == dst {
		return "", "", false, false
	}

	srcInvalid = isReservedOrInvalidIP(src)
	dstInvalid = isReservedOrInvalidIP(dst)

	if srcInvalid || dstInvalid {
		return "", "", srcInvalid, dstInvalid
	}

	return src, dst, false, false
}

// Helper to get logParts keys for logging
func logPartsKeys(logParts map[string]interface{}) []string {
	keys := make([]string, 0, len(logParts))
	for k := range logParts {
		keys = append(keys, k)
	}
	return keys
}

func extractIPsFromAllFields(msg string) []string {
	var ips []string
	seen := make(map[string]bool)

	// Split on common delimiters: space, comma, tab, pipe, semicolon
	delimiters := []string{" ", ",", "\t", "|", ";", "="}
	fields := []string{msg}

	// Recursively split by each delimiter
	for _, delim := range delimiters {
		var newFields []string
		for _, field := range fields {
			newFields = append(newFields, strings.Split(field, delim)...)
		}
		fields = newFields
	}

	// Try to parse each field as an IP
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}

		// Try to parse as IP
		if ip := net.ParseIP(field); ip != nil {
			ipStr := ip.String()
			// Avoid duplicates and skip link-local/loopback
			if !seen[ipStr] {
				seen[ipStr] = true
				ips = append(ips, ipStr)
			}
		}
	}

	return ips
}

func extractIPsFromJSON(msg string) []string {
	var ips []string
	seen := make(map[string]bool)

	var data interface{}
	if err := json.Unmarshal([]byte(msg), &data); err != nil {
		return ips
	}

	// Recursively extract all string values and try to parse as IPs
	extractIPsFromValue(data, &ips, seen)
	return ips
}

func extractIPsFromValue(v interface{}, ips *[]string, seen map[string]bool) {
	switch val := v.(type) {
	case map[string]interface{}:
		for _, value := range val {
			extractIPsFromValue(value, ips, seen)
		}
	case []interface{}:
		for _, item := range val {
			extractIPsFromValue(item, ips, seen)
		}
	case string:
		if ip := net.ParseIP(val); ip != nil {
			ipStr := ip.String()
			if !seen[ipStr] {
				seen[ipStr] = true
				*ips = append(*ips, ipStr)
			}
		}
	}
}

func extractIPsFromXML(msg string) []string {
	var ips []string
	seen := make(map[string]bool)

	// Use regex to extract text content from XML tags
	re := regexp.MustCompile(`>([^<]+)<`)
	matches := re.FindAllStringSubmatch(msg, -1)

	for _, match := range matches {
		if len(match) > 1 {
			content := strings.TrimSpace(match[1])
			if ip := net.ParseIP(content); ip != nil {
				ipStr := ip.String()
				if !seen[ipStr] {
					seen[ipStr] = true
					ips = append(ips, ipStr)
				}
			}
		}
	}

	return ips
}

// Detect if message is JSON or XML
func detectStructuredFormat(msg string) string {
	msg = strings.TrimSpace(msg)

	// Check for JSON
	if (strings.HasPrefix(msg, "{") && strings.HasSuffix(msg, "}")) ||
		(strings.HasPrefix(msg, "[") && strings.HasSuffix(msg, "]")) {
		// Try to parse to confirm
		var data interface{}
		if json.Unmarshal([]byte(msg), &data) == nil {
			return "json"
		}
	}

	// Check for XML
	if strings.HasPrefix(msg, "<") && strings.HasSuffix(msg, ">") {
		return "xml"
	}

	return ""
}
