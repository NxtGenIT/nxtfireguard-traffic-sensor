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
		if validSrc, validDst, srcInvalid, dstInvalid := validateSrcDst(srcCEF, dstCEF); validSrc != "" && validDst != "" {
			zap.L().Debug("Extracted source and destination from CEF",
				zap.String("src", validSrc),
				zap.String("dst", validDst),
			)
			return validSrc, validDst, msg
		} else if srcInvalid || dstInvalid {
			zap.L().Debug("CEF IPs found but filtered as invalid",
				zap.String("src", srcCEF),
				zap.String("dst", dstCEF),
				zap.Bool("srcInvalid", srcInvalid),
				zap.Bool("dstInvalid", dstInvalid),
			)
			return "", "", msg
		}
	}

	// Try to extract src/dst from Cisco-style logs
	if srcCisco, dstCisco := extractCiscoIosSrcDst(msg); srcCisco != "" && dstCisco != "" {
		if validSrc, validDst, srcInvalid, dstInvalid := validateSrcDst(srcCisco, dstCisco); validSrc != "" && validDst != "" {
			zap.L().Debug("Extracted source and destination from Cisco",
				zap.String("src", validSrc),
				zap.String("dst", validDst),
			)
			return validSrc, validDst, msg
		} else if srcInvalid || dstInvalid {
			zap.L().Debug("Cisco IPs found but filtered as invalid",
				zap.String("src", srcCisco),
				zap.String("dst", dstCisco),
				zap.Bool("srcInvalid", srcInvalid),
				zap.Bool("dstInvalid", dstInvalid),
			)
			return "", "", msg
		}
	}

	// Try to extract src/dst from pfSense filterlog format
	if srcPf, dstPf := extractPfSenseSrcDst(msg); srcPf != "" && dstPf != "" {
		if validSrc, validDst, srcInvalid, dstInvalid := validateSrcDst(srcPf, dstPf); validSrc != "" && validDst != "" {
			zap.L().Debug("Extracted source and destination from pfSense",
				zap.String("src", validSrc),
				zap.String("dst", validDst),
			)
			return validSrc, validDst, msg
		} else if srcInvalid || dstInvalid {
			zap.L().Debug("pfSense IPs found but filtered as invalid",
				zap.String("src", srcPf),
				zap.String("dst", dstPf),
				zap.Bool("srcInvalid", srcInvalid),
				zap.Bool("dstInvalid", dstInvalid),
			)
			return "", "", msg
		}
	}

	// Detect and handle structured formats
	format := detectStructuredFormat(msg)
	var ipsStructured []string

	switch format {
	case "json":
		ipsStructured = extractIPsFromJSON(msg)
		if len(ipsStructured) >= 2 {
			for i := 0; i < len(ipsStructured)-1; i++ {
				for j := i + 1; j < len(ipsStructured); j++ {
					if validSrc, validDst, srcInvalid, dstInvalid := validateSrcDst(ipsStructured[i], ipsStructured[j]); validSrc != "" && validDst != "" {
						zap.L().Debug("Extracted source and destination from JSON",
							zap.Strings("ips", ipsStructured),
							zap.String("src", validSrc),
							zap.String("dst", validDst),
						)
						return validSrc, validDst, msg
					} else if srcInvalid || dstInvalid {
						zap.L().Debug("JSON IPs found but filtered as invalid",
							zap.String("src", ipsStructured[i]),
							zap.String("dst", ipsStructured[j]),
							zap.Bool("srcInvalid", srcInvalid),
							zap.Bool("dstInvalid", dstInvalid),
						)
						return "", "", msg
					}
				}
			}
		}
	case "xml":
		ipsStructured = extractIPsFromXML(msg)
		if len(ipsStructured) >= 2 {
			for i := 0; i < len(ipsStructured)-1; i++ {
				for j := i + 1; j < len(ipsStructured); j++ {
					if validSrc, validDst, srcInvalid, dstInvalid := validateSrcDst(ipsStructured[i], ipsStructured[j]); validSrc != "" && validDst != "" {
						zap.L().Debug("Extracted source and destination from XML",
							zap.Strings("ips", ipsStructured),
							zap.String("src", validSrc),
							zap.String("dst", validDst),
						)
						return validSrc, validDst, msg
					} else if srcInvalid || dstInvalid {
						zap.L().Debug("XML IPs found but filtered as invalid",
							zap.String("src", ipsStructured[i]),
							zap.String("dst", ipsStructured[j]),
							zap.Bool("srcInvalid", srcInvalid),
							zap.Bool("dstInvalid", dstInvalid),
						)
						return "", "", msg
					}
				}
			}
		}
	}

	// Fallback 1: extract all IPs and use first two uniqe ones as src/dst
	ips := extractIPs(msg)
	if len(ips) >= 2 {
		for i := 0; i < len(ips)-1; i++ {
			for j := i + 1; j < len(ips); j++ {
				if validSrc, validDst, srcInvalid, dstInvalid := validateSrcDst(ips[i], ips[j]); validSrc != "" && validDst != "" {
					zap.L().Debug("Extracted source and destination from IPs",
						zap.Strings("ips", ips),
						zap.String("src", validSrc),
						zap.String("dst", validDst),
					)
					return validSrc, validDst, msg
				} else if srcInvalid || dstInvalid {
					zap.L().Debug("IPs found but filtered as invalid",
						zap.String("src", ips[i]),
						zap.String("dst", ips[j]),
						zap.Bool("srcInvalid", srcInvalid),
						zap.Bool("dstInvalid", dstInvalid),
					)
					return "", "", msg
				}
			}
		}
	}

	// Fallback 2: try parsing every field as an IP
	ipsFromFields := extractIPsFromAllFields(msg)
	if len(ipsFromFields) >= 2 {
		for i := 0; i < len(ipsFromFields)-1; i++ {
			for j := i + 1; j < len(ipsFromFields); j++ {
				if validSrc, validDst, srcInvalid, dstInvalid := validateSrcDst(ipsFromFields[i], ipsFromFields[j]); validSrc != "" && validDst != "" {
					zap.L().Warn("Extracted source and destination using field-by-field parsing (no structured format matched)",
						zap.Strings("ips", ipsFromFields),
						zap.String("src", validSrc),
						zap.String("dst", validDst),
						zap.String("message", msg),
					)
					return validSrc, validDst, msg
				} else if srcInvalid || dstInvalid {
					zap.L().Debug("Field-parsed IPs found but filtered as invalid",
						zap.String("src", ipsFromFields[i]),
						zap.String("dst", ipsFromFields[j]),
						zap.Bool("srcInvalid", srcInvalid),
						zap.Bool("dstInvalid", dstInvalid),
					)
					return "", "", msg
				}
			}
		}
	}

	zap.L().Warn("No source or destination found in message",
		zap.String("message", msg),
	)
	return "", "", msg
}
