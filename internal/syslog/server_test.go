package syslog

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/flow"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func TestServerUDPAndTCP(t *testing.T) {
	addr := freeAddr(t)
	var mu sync.Mutex
	var got []string
	emit := func(f flow.Flow) {
		mu.Lock()
		got = append(got, fmt.Sprintf("%s %s>%s", f.Source.Name, f.Src, f.Dst))
		mu.Unlock()
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- Run(ctx, addr, emit, func() { close(ready) }) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatal(err)
	}

	udp, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	// The host field is an address too; it must not be taken as source.
	_, _ = fmt.Fprint(udp, "<134>Jan  1 00:00:00 10.9.9.9 sshd[1]: Failed password from 203.0.113.5 port 22 to 192.168.1.2\n")
	_, _ = fmt.Fprint(udp, "<134>1 2026-01-01T00:00:00Z 10.9.9.9 suricata - - - {\"src_ip\":\"203.0.113.6\",\"dest_ip\":\"192.168.1.3\"}")
	_ = udp.Close()

	tcp, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	line := "<134>Jan  1 00:00:00 fw filterlog: 5,,,1,igb0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,203.0.113.7,192.168.1.4,1,2,0,S,1,,1,,mss"
	_, _ = fmt.Fprintf(tcp, "%s\n%d %s", line, len(line), line) // newline framing, then octet counting
	_ = tcp.Close()

	want := map[string]bool{
		"127.0.0.1 203.0.113.5>192.168.1.2": false,
		"127.0.0.1 203.0.113.6>192.168.1.3": false,
		"127.0.0.1 203.0.113.7>192.168.1.4": false,
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n >= 4 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, g := range got {
		if _, ok := want[g]; !ok {
			t.Errorf("unexpected flow %s", g)
		}
		want[g] = true
	}
	for w, seen := range want {
		if !seen {
			t.Errorf("missing flow %s (got %v)", w, got)
		}
	}
	if len(got) != 4 {
		t.Errorf("want 4 flows (one TCP line sent twice), got %d", len(got))
	}

	// The port is free again after Run returned.
	l, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("port still bound: %v", err)
	}
	_ = l.Close()
}

func TestServerReportsBindFailure(t *testing.T) {
	addr := freeAddr(t)
	l, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	err = Run(context.Background(), addr, func(flow.Flow) {}, func() { t.Error("ready although bind failed") })
	if err == nil {
		t.Fatal("no error for a bound port")
	}
}
