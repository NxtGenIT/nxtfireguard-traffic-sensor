package syslog

import (
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"strings"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/flow"
)

// Extract finds the source and destination address of the connection a log
// line describes. Formats that name source and destination explicitly (CEF
// and key=value, Cisco arrows, pf filterlog, JSON with known field names)
// are tried first, and their answer is final even if an address turns out
// unscorable. Otherwise the first two distinct scorable addresses in the
// line are taken, in order of appearance.
func Extract(msg string) (src, dst netip.Addr, ok bool) {
	for _, explicit := range []func(string) (netip.Addr, netip.Addr, bool){keyValue, arrow, filterlog} {
		if src, dst, ok := explicit(msg); ok {
			return src, dst, true
		}
	}
	trimmed := strings.TrimSpace(msg)
	switch {
	case strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "["):
		if addrs, src, dst, ok := fromJSON(trimmed); ok {
			return src, dst, true
		} else if addrs != nil {
			return firstTwo(addrs)
		}
	case strings.HasPrefix(trimmed, "<") && strings.HasSuffix(trimmed, ">"):
		return firstTwo(xmlText(trimmed))
	}
	return firstTwo(scan(msg))
}

var addrChars = `[0-9A-Fa-f:.]+`

// keyValuePairs are source/destination key names as they appear in CEF
// extensions (src, dst) and FortiGate-style logs (srcip, dstip).
var keyValuePairs = [][2]*regexp.Regexp{
	{kv("src"), kv("dst")},
	{kv("srcip"), kv("dstip")},
}

func kv(key string) *regexp.Regexp {
	return regexp.MustCompile(`(?:^|[\s|,;])` + key + `=` + `"?(` + addrChars + `)`)
}

func keyValue(msg string) (netip.Addr, netip.Addr, bool) {
	for _, pair := range keyValuePairs {
		s, sok := firstAddr(pair[0], msg)
		d, dok := firstAddr(pair[1], msg)
		if sok && dok {
			return s, d, true
		}
	}
	return netip.Addr{}, netip.Addr{}, false
}

func firstAddr(re *regexp.Regexp, msg string) (netip.Addr, bool) {
	m := re.FindStringSubmatch(msg)
	if m == nil {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(m[1])
	return a, err == nil
}

// arrowRe matches Cisco IOS/ASA access-list logs: "a.b.c.d(port) -> e.f.g.h(port)".
var arrowRe = regexp.MustCompile(`(` + addrChars + `)\(\d+\)\s*->\s*(?:\S+/)?(` + addrChars + `)\(\d+\)`)

func arrow(msg string) (netip.Addr, netip.Addr, bool) {
	m := arrowRe.FindStringSubmatch(msg)
	if m == nil {
		return netip.Addr{}, netip.Addr{}, false
	}
	s, err1 := netip.ParseAddr(m[1])
	d, err2 := netip.ParseAddr(m[2])
	return s, d, err1 == nil && err2 == nil
}

// filterlog reads pfSense/OPNsense filterlog CSV. Field 8 is the IP version;
// the addresses follow the version-specific header fields.
func filterlog(msg string) (netip.Addr, netip.Addr, bool) {
	f := strings.Split(msg, ",")
	if len(f) < 9 {
		return netip.Addr{}, netip.Addr{}, false
	}
	var si, di int
	switch strings.TrimSpace(f[8]) {
	case "4":
		si, di = 18, 19
	case "6":
		si, di = 15, 16
	default:
		return netip.Addr{}, netip.Addr{}, false
	}
	if len(f) <= di {
		return netip.Addr{}, netip.Addr{}, false
	}
	s, err1 := netip.ParseAddr(strings.TrimSpace(f[si]))
	d, err2 := netip.ParseAddr(strings.TrimSpace(f[di]))
	return s, d, err1 == nil && err2 == nil
}

// jsonPairs are source/destination field paths, most specific first:
// Suricata EVE, common variants, Elastic Common Schema, Azure/Sentinel.
var jsonPairs = [][2]string{
	{"src_ip", "dest_ip"},
	{"src_ip", "dst_ip"},
	{"source.ip", "destination.ip"},
	{"srcip", "dstip"},
	{"src", "dst"},
	{"sourceaddress", "destinationaddress"},
	{"srcaddr", "dstaddr"},
}

// fromJSON returns the first known source/destination field pair. Without
// one it returns every address-valued string in document order. A message
// that is not valid JSON yields nil, false.
func fromJSON(msg string) (addrs []netip.Addr, src, dst netip.Addr, ok bool) {
	fields, err := flattenJSON(msg)
	if err != nil {
		return nil, src, dst, false
	}
	var found []jsonAddr
	addrs = []netip.Addr{}
	for _, f := range fields {
		if a, err := netip.ParseAddr(f.value); err == nil {
			addrs = append(addrs, a)
			found = append(found, jsonAddr{strings.ToLower(f.path), a})
		}
	}
	for _, pair := range jsonPairs {
		s, sok := byKey(found, pair[0])
		d, dok := byKey(found, pair[1])
		if sok && dok {
			return addrs, s, d, true
		}
	}
	return addrs, src, dst, false
}

type jsonAddr struct {
	path string
	addr netip.Addr
}

// byKey finds the first field whose path is key or ends in ".key".
func byKey(found []jsonAddr, key string) (netip.Addr, bool) {
	for _, f := range found {
		if f.path == key || strings.HasSuffix(f.path, "."+key) {
			return f.addr, true
		}
	}
	return netip.Addr{}, false
}

type jsonField struct{ path, value string }

// flattenJSON lists every string value with its dotted object path, in
// document order (encoding/json maps would lose the order).
func flattenJSON(msg string) ([]jsonField, error) {
	dec := json.NewDecoder(strings.NewReader(msg))
	var out []jsonField
	var walk func(path string) error
	walk = func(path string) error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				for dec.More() {
					k, err := dec.Token()
					if err != nil {
						return err
					}
					key, _ := k.(string)
					child := key
					if path != "" {
						child = path + "." + key
					}
					if err := walk(child); err != nil {
						return err
					}
				}
			case '[':
				for dec.More() {
					if err := walk(path); err != nil {
						return err
					}
				}
			}
			_, err := dec.Token() // closing delimiter
			return err
		case string:
			out = append(out, jsonField{path, t})
		}
		return nil
	}
	if err := walk(""); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after JSON value")
	}
	return out, nil
}

var xmlTextRe = regexp.MustCompile(`>\s*([^<]+?)\s*<`)

// xmlText returns the addresses that are the full text of an element.
func xmlText(msg string) []netip.Addr {
	var out []netip.Addr
	for _, m := range xmlTextRe.FindAllStringSubmatch(msg, -1) {
		if a, err := netip.ParseAddr(m[1]); err == nil {
			out = append(out, a)
		}
	}
	return out
}

var (
	candidateRe = regexp.MustCompile(addrChars)
	ipv4Re      = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
)

// scan finds addresses in free text, including ones followed by a port
// ("1.2.3.4:443", "1.2.3.4/443").
func scan(msg string) []netip.Addr {
	var out []netip.Addr
	for _, c := range candidateRe.FindAllString(msg, -1) {
		if a, err := netip.ParseAddr(c); err == nil {
			out = append(out, a)
			continue
		}
		// End of a sentence or a "host:" label.
		if a, err := netip.ParseAddr(strings.TrimRight(c, ".:")); err == nil {
			out = append(out, a)
			continue
		}
		for _, v4 := range ipv4Re.FindAllString(c, -1) {
			if a, err := netip.ParseAddr(v4); err == nil {
				out = append(out, a)
			}
		}
	}
	return out
}

// firstTwo picks the first two distinct scorable addresses.
func firstTwo(addrs []netip.Addr) (netip.Addr, netip.Addr, bool) {
	var first netip.Addr
	for _, a := range addrs {
		a = flow.Canonical(a)
		if !flow.Scorable(a) {
			continue
		}
		if !first.IsValid() {
			first = a
		} else if a != first {
			return first, a, true
		}
	}
	return netip.Addr{}, netip.Addr{}, false
}
