package syslog

import (
	"bufio"
	"os"
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
