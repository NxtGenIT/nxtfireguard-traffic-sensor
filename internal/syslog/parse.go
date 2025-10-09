package syslog

import "go.uber.org/zap"

func inferSrcDst(logParts map[string]interface{}) (src, dst, msg string) {
	var msgField string

	// Determine which field contains the message
	if m, ok := logParts["content"].(string); ok {
		msg = m
		msgField = "content"
	} else if m, ok := logParts["message"].(string); ok {
		msg = m
		msgField = "message"
	} else if m, ok := logParts["msg"].(string); ok {
		msg = m
		msgField = "msg"
	} else {
		zap.L().Warn("No message found in logParts",
			zap.Any("logPartsKeys", logPartsKeys(logParts)),
		)
		return "", "", ""
	}

	zap.L().Debug("Extracted message from logParts",
		zap.String("field", msgField),
		zap.String("message", msg),
	)

	// Try to extract src/dst from CEF-style logs
	if srcCEF, dstCEF := extractCEFSrcDst(msg); srcCEF != "" && dstCEF != "" {
		if src, dst := validateSrcDst(srcCEF, dstCEF); src != "" && dst != "" {

			zap.L().Debug("Extracted source and destination from CEF",
				zap.String("src", srcCEF),
				zap.String("dst", dstCEF),
			)
			return srcCEF, dstCEF, msg
		}
	}

	// Try to extract src/dst from Cisco-style logs
	if srcCisco, dstCisco := extractCiscoIosSrcDst(msg); srcCisco != "" && dstCisco != "" {
		if src, dst := validateSrcDst(srcCisco, dstCisco); src != "" && dst != "" {

			zap.L().Debug("Extracted source and destination from Cisco",
				zap.String("src", srcCisco),
				zap.String("dst", dstCisco),
			)
			return srcCisco, dstCisco, msg
		}
	}

	// Fallback: extract all IPs and use first two uniqe ones as src/dst
	ips := extractIPs(msg)
	if len(ips) >= 2 {
		for i := 0; i < len(ips)-1; i++ {
			for j := i + 1; j < len(ips); j++ {
				if src, dst := validateSrcDst(ips[i], ips[j]); src != "" && dst != "" {
					zap.L().Debug("Extracted source and destination from IPs",
						zap.Strings("ips", ips),
						zap.String("src", src),
						zap.String("dst", dst),
					)
					return src, dst, msg
				}
			}
		}
	}

	zap.L().Warn("No source or destination found in message",
		zap.String("message", msg),
	)
	return "", "", msg
}
