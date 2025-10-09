package types

// Indicates the source on which we received a traffic event
type Source struct {
	SourceType string `json:"source_type"` // syslog or interface
	SourceName string `json:"source_name"` // IP or iface name
}

type Decision struct {
	Block     bool   `json:"block"`
	Reason    string `json:"reason"`
	Blocklist string `json:"blocklist"`
}

type Blocklist struct {
	ID                          int    `json:"id"`
	Name                        string `json:"name"`
	ShouldIncludePrivateIPs     bool   `json:"shouldIncludePrivateIPs"`
	ShouldIncludePublicIPs      bool   `json:"shouldIncludePublicIPs"`
	NfgScoreThresholdPrivateIPs int32  `json:"nfgScoreThresholdPrivateIPs"`
	NfgScoreThresholdPublicIPs  int32  `json:"nfgScoreThresholdPublicIPs"`
}

type BlocklistsResponse struct {
	Blocklists []Blocklist `json:"blocklists"`
}

type AlertThresholdResponse struct {
	AlertThreshold int32 `json:"alertThreshold"`
}

type ScoreRecord struct {
	IP       string `json:"ip"`
	NFGScore int32  `json:"nfg_score"`
}

type PacketInfo struct {
	// Common fields
	Src           string  `json:"source_ip,omitempty"`
	Dst           string  `json:"destination_ip,omitempty"`
	SrcPort       *uint16 `json:"source_port,omitempty"`
	DstPort       *uint16 `json:"destination_port,omitempty"`
	CaptureSource string  `json:"capture_source"` // "interface" or "syslog"

	// Ethernet
	SrcMAC       string `json:"source_mac,omitempty"`
	DstMAC       string `json:"destination_mac,omitempty"`
	EthernetType string `json:"ethernet_type,omitempty"`

	// ARP
	ARPSourceIP  string `json:"arp_source_ip,omitempty"`
	ARPDestIP    string `json:"arp_destination_ip,omitempty"`
	ARPSourceMAC string `json:"arp_source_mac,omitempty"`
	ARPDestMAC   string `json:"arp_destination_mac,omitempty"`
	ARPOperation string `json:"arp_operation,omitempty"`

	// IPv4/IPv6
	Version    *uint8  `json:"version,omitempty"`
	IHL        *uint8  `json:"ihl,omitempty"`
	TOS        *uint8  `json:"tos,omitempty"`
	Length     *uint16 `json:"length,omitempty"`
	ID         *uint16 `json:"id,omitempty"`
	Flags      *string `json:"flags,omitempty"`
	FragOffset *uint16 `json:"frag_offset,omitempty"`
	TTL        *uint8  `json:"ttl,omitempty"`
	Protocol   *string `json:"protocol,omitempty"`
	Checksum   *uint16 `json:"checksum,omitempty"`
	Options    *string `json:"options,omitempty"`
	Padding    *string `json:"padding,omitempty"`
	FlowLabel  *uint32 `json:"flow_label,omitempty"` // IPv6 only

	// TCP
	TCPSeq     *uint32 `json:"tcp_seq,omitempty"`
	TCPAck     *uint32 `json:"tcp_ack,omitempty"`
	TCPFlags   *string `json:"tcp_flags,omitempty"`
	TCPWindow  *uint16 `json:"tcp_window,omitempty"`
	TCPOffset  *uint8  `json:"tcp_offset,omitempty"`
	TCPOptions *string `json:"tcp_options,omitempty"`

	// ICMP
	ICMPType     *uint8  `json:"icmp_type,omitempty"`
	ICMPCode     *uint8  `json:"icmp_code,omitempty"`
	ICMPChecksum *uint16 `json:"icmp_checksum,omitempty"`
	ICMPId       *uint16 `json:"icmp_id,omitempty"`
	ICMPSeq      *uint16 `json:"icmp_seq,omitempty"`

	// DNS
	DNSID       *uint16 `json:"dns_id,omitempty"`
	DNSQuery    *string `json:"dns_query,omitempty"`
	DNSAnswer   *string `json:"dns_answer,omitempty"`
	DNSOpCode   *string `json:"dns_op_code,omitempty"`
	DNSResponse *bool   `json:"dns_response,omitempty"`
	DNSError    *string `json:"dns_error,omitempty"`

	// Interface name
	Interface *string `json:"interface,omitempty"`

	// Raw/capture data
	PacketBase64    *string `json:"packet_base64,omitempty"`
	PacketRawBase64 *string `json:"packet_raw_base64,omitempty"`

	// CaptureInfo (omitted for syslog)
	CaptureTimestamp *int64 `json:"timestamp,omitempty"`
	CaptureLength    *int   `json:"capture_length,omitempty"`
	OrigLength       *int   `json:"orig_length,omitempty"`

	TrafficSensorName string `json:"traffic_sensor_name,omitempty"`

	// Raw Syslog message (omitted for interface)
	RawSyslogMessage *string `json:"raw_syslog_message,omitempty"`
}

type WhitelistResponse struct {
	CIDRs []string `json:"cidrs"`
}
