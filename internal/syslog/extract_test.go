package syslog

import (
	"bufio"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestExtractCorpus(t *testing.T) {
	f, err := os.Open("testdata/corpus.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		want, msg, ok := strings.Cut(line, "\t")
		if !ok {
			t.Fatalf("malformed corpus line %q", line)
		}
		n++
		// Several runs: an earlier implementation depended on map order.
		for range 5 {
			src, dst, ok := Extract(msg)
			got := "-"
			if ok {
				got = src.String() + "|" + dst.String()
			}
			if got != want {
				t.Errorf("Extract(%q) = %s, want %s", msg, got, want)
				break
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if n < 20 {
		t.Fatalf("corpus has only %d cases", n)
	}
}

func FuzzExtract(f *testing.F) {
	f.Add("5,,,1,igb0,match,block,in,6,0,0,64,tcp,6,40,2001:db8::1")
	f.Add(`{"src_ip":[{"x":"1.2.3.4"}]}`)
	f.Add("CEF:0|a|b|1|1|x|5|src=1.2.3.4 dst=")
	f.Fuzz(func(t *testing.T, msg string) {
		src, dst, ok := Extract(msg)
		if ok && (!src.IsValid() || !dst.IsValid()) {
			t.Fatalf("ok with invalid address: %v %v", src, dst)
		}
	})
}

// A deeply nested 64 KiB JSON line must be cheap to reject: building every
// parent path used to cost hundreds of MB per message.
func TestDeepJSONIsBounded(t *testing.T) {
	depth := 60 * 1024 / 6
	msg := strings.Repeat(`{"a":`, depth) + `"1.2.3.4"` + strings.Repeat("}", depth)
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	before := m.TotalAlloc
	if _, err := flattenJSON(msg); !errors.Is(err, errJSONTooDeep) {
		t.Errorf("err = %v, want errJSONTooDeep", err)
	}
	runtime.ReadMemStats(&m)
	if used := m.TotalAlloc - before; used > 1<<20 {
		t.Errorf("rejecting deep JSON allocated %d KB", used>>10)
	}
	Extract(msg) // falls through to the free-text scan, which must cope
	if _, err := flattenJSON(strings.Repeat(`{"a":`, maxJSONDepth+2) + `"x"` + strings.Repeat("}", maxJSONDepth+2)); !errors.Is(err, errJSONTooDeep) {
		t.Errorf("err = %v, want errJSONTooDeep", err)
	}
	ok := strings.Repeat(`{"a":`, 5) + `{"src_ip":"203.0.113.1","dest_ip":"198.51.100.2"}` + strings.Repeat("}", 5)
	if src, dst, found := Extract(ok); !found || src.String() != "203.0.113.1" || dst.String() != "198.51.100.2" {
		t.Errorf("normal nesting broke: %v %v %v", src, dst, found)
	}
}
