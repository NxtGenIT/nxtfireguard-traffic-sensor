package scores

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/nfg"
)

var now = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "scores.db"), 100)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return now }
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func score(t *testing.T, s *Store, ip string) int32 {
	t.Helper()
	v, err := s.Score(netip.MustParseAddr(ip))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func snapshot(rows ...nfg.Score) func(func(nfg.Score) error) error {
	return func(add func(nfg.Score) error) error {
		for _, r := range rows {
			if err := add(r); err != nil {
				return err
			}
		}
		return nil
	}
}

func TestDecay(t *testing.T) {
	for _, c := range []struct {
		age  time.Duration
		want int32
	}{
		{0, 100},
		{-time.Hour, 100}, // clock skew must not raise a score
		{72 * time.Hour, 50},
		{144 * time.Hour, 30}, // 25 would be below the floor
		{1000 * time.Hour, 30},
	} {
		if got := Decay(100, now.Add(-c.age), now); got != c.want {
			t.Errorf("Decay(100, age %s) = %d, want %d", c.age, got, c.want)
		}
	}
	if Decay(0, now.Add(-time.Hour), now) != 0 {
		t.Error("zero stays zero")
	}
}

func TestUnknownIPScoresZero(t *testing.T) {
	if got := score(t, open(t), "203.0.113.1"); got != 0 {
		t.Fatalf("got %d", got)
	}
}

func TestLiveUpdateKeepsItsTimestamp(t *testing.T) {
	s := open(t)
	ip := "203.0.113.1"
	if score(t, s, ip) != 0 {
		t.Fatal("expected unknown IP") // also puts the miss in the cache
	}
	if err := s.Put(nfg.Score{IP: ip, Score: 90, LastUpdated: now.Add(-72 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if got := score(t, s, ip); got != 45 {
		t.Fatalf("after put: %d, want 45 (cache must be invalidated, decay applied)", got)
	}
	// Without a timestamp the update counts as current, not as decades old.
	if err := s.Put(nfg.Score{IP: ip, Score: 90}); err != nil {
		t.Fatal(err)
	}
	if got := score(t, s, ip); got != 90 {
		t.Fatalf("zero timestamp: %d, want 90", got)
	}
}

func TestReplaceAll(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if _, err := s.ReplaceAll(ctx, snapshot(
		nfg.Score{IP: "203.0.113.1", Score: 80, LastUpdated: now},
		nfg.Score{IP: "203.0.113.2", Score: 70, LastUpdated: now},
	)); err != nil {
		t.Fatal(err)
	}
	if score(t, s, "203.0.113.1") != 80 || score(t, s, "203.0.113.2") != 70 {
		t.Fatal("first snapshot not loaded")
	}

	n, err := s.ReplaceAll(ctx, func(add func(nfg.Score) error) error {
		if err := add(nfg.Score{IP: "203.0.113.1", Score: 60, LastUpdated: now.Add(-time.Minute)}); err != nil {
			return err
		}
		// Live updates arriving while the snapshot downloads.
		if err := s.Put(nfg.Score{IP: "203.0.113.1", Score: 99, LastUpdated: now}); err != nil {
			return err
		}
		if err := s.Put(nfg.Score{IP: "203.0.113.3", Score: 55, LastUpdated: now}); err != nil {
			return err
		}
		if err := s.Put(nfg.Score{IP: "203.0.113.4", Score: 11, LastUpdated: now.Add(-time.Hour)}); err != nil {
			return err
		}
		return add(nfg.Score{IP: "203.0.113.4", Score: 44, LastUpdated: now})
	})
	if err != nil || n.Rows != 2 || n.Merged {
		t.Fatalf("ReplaceAll = %+v, %v", n, err)
	}
	for ip, want := range map[string]int32{
		"203.0.113.1": 99, // live update newer than snapshot row
		"203.0.113.2": 0,  // not in snapshot any more: removed
		"203.0.113.3": 55, // live update for an IP the snapshot lacks
		"203.0.113.4": 44, // snapshot row newer than live update
	} {
		if got := score(t, s, ip); got != want {
			t.Errorf("%s = %d, want %d", ip, got, want)
		}
	}
}

func TestReplaceAllFailureKeepsTable(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if _, err := s.ReplaceAll(ctx, snapshot(nfg.Score{IP: "203.0.113.1", Score: 80, LastUpdated: now})); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("connection reset")
	_, err := s.ReplaceAll(ctx, func(add func(nfg.Score) error) error {
		for i := range snapshotChunk + 10 { // crosses a chunk commit
			if err := add(nfg.Score{IP: netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}).String(), Score: 1}); err != nil {
				return err
			}
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if score(t, s, "203.0.113.1") != 80 || score(t, s, "198.51.0.1") != 0 {
		t.Fatal("failed snapshot must leave the previous table untouched")
	}
	if _, err := s.ReplaceAll(ctx, snapshot(nfg.Score{IP: "203.0.113.9", Score: 5, LastUpdated: now})); err != nil {
		t.Fatalf("snapshot after a failed one: %v", err)
	}
}

func TestEmptySnapshotKeepsTable(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if snap, err := s.ReplaceAll(ctx, snapshot()); err != nil || snap.Rows != 0 {
		t.Fatalf("empty snapshot into an empty table: %+v, %v", snap, err)
	}
	if _, err := s.ReplaceAll(ctx, snapshot(nfg.Score{IP: "203.0.113.1", Score: 80, LastUpdated: now})); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReplaceAll(ctx, snapshot()); !errors.Is(err, ErrEmptySnapshot) {
		t.Fatalf("err = %v, want ErrEmptySnapshot", err)
	}
	if score(t, s, "203.0.113.1") != 80 {
		t.Fatal("empty snapshot must not wipe the scores")
	}
}

func TestSmallSnapshotIsMerged(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	var full []nfg.Score
	for i := range 10 {
		full = append(full, nfg.Score{IP: netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}).String(), Score: 50, LastUpdated: now})
	}
	if _, err := s.ReplaceAll(ctx, snapshot(full...)); err != nil {
		t.Fatal(err)
	}
	// 4 of 10: probably truncated. Keep what the snapshot lacks, take what it has.
	snap, err := s.ReplaceAll(ctx, snapshot(
		nfg.Score{IP: "198.51.100.0", Score: 90, LastUpdated: now},
		nfg.Score{IP: "198.51.100.1", Score: 90, LastUpdated: now},
		nfg.Score{IP: "198.51.100.2", Score: 90, LastUpdated: now},
		nfg.Score{IP: "203.0.113.7", Score: 90, LastUpdated: now},
	))
	if err != nil || !snap.Merged || snap.Rows != 4 {
		t.Fatalf("ReplaceAll = %+v, %v", snap, err)
	}
	if score(t, s, "198.51.100.0") != 90 || score(t, s, "198.51.100.9") != 50 || score(t, s, "203.0.113.7") != 90 {
		t.Fatal("merge must keep old rows and take the snapshot's")
	}
	// 6 of 11 is plausible: replace, the missing ones go.
	snap, err = s.ReplaceAll(ctx, snapshot(full[:6]...))
	if err != nil || snap.Merged {
		t.Fatalf("ReplaceAll = %+v, %v", snap, err)
	}
	if score(t, s, "198.51.100.9") != 0 {
		t.Fatal("a plausible snapshot replaces the table")
	}
}

func TestNormalizesIPKeys(t *testing.T) {
	s := open(t)
	if err := s.Put(nfg.Score{IP: "2001:0db8:0000::0001", Score: 70, LastUpdated: now}); err != nil {
		t.Fatal(err)
	}
	if got := score(t, s, "2001:db8::1"); got != 70 {
		t.Fatalf("got %d", got)
	}
}

func TestOpensDatabaseOfEarlierRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE ip_scores (ip TEXT PRIMARY KEY, score INTEGER, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO ip_scores (updated_at, ip, score) VALUES (?, ?, ?)`, now, "203.0.113.1", 77); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	s, err := Open(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	s.now = func() time.Time { return now }
	if got := score(t, s, "203.0.113.1"); got != 77 {
		t.Fatalf("got %d", got)
	}
}

func TestState(t *testing.T) {
	s := open(t)
	var v []string
	if ok, err := s.LoadState("k", &v); ok || err != nil {
		t.Fatalf("empty: %v %v", ok, err)
	}
	if err := s.SaveState("k", []string{"a"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.LoadState("k", &v); !ok || err != nil || len(v) != 1 || v[0] != "a" {
		t.Fatalf("got %v %v %v", ok, err, v)
	}
}

// Rows of earlier releases carry no time; they were served at the floor
// and must not jump back to full weight.
func TestLegacyRowWithoutTimeIsAtTheFloor(t *testing.T) {
	if got := Decay(100, time.Time{}, now); got != 30 {
		t.Errorf("zero time: %d, want 30", got)
	}
	s := open(t)
	if _, err := s.db.Exec(`INSERT INTO ip_scores (ip, score, updated_at) VALUES (?, ?, ?)`, "203.0.113.5", 100, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if got := score(t, s, "203.0.113.5"); got != 30 {
		t.Errorf("legacy row: %d, want 30", got)
	}
}

// Merged rows must not count towards the next comparison, and a real
// shrink must win after a few snapshots.
func TestRepeatedSmallSnapshotsEventuallyReplace(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	rows := func(n int) []nfg.Score {
		var out []nfg.Score
		for i := range n {
			out = append(out, nfg.Score{IP: netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}).String(), Score: 50, LastUpdated: now})
		}
		return out
	}
	if _, err := s.ReplaceAll(ctx, snapshot(rows(100)...)); err != nil {
		t.Fatal(err)
	}
	for i := range maxMerges {
		snap, err := s.ReplaceAll(ctx, snapshot(rows(40)...))
		if err != nil || !snap.Merged {
			t.Fatalf("small snapshot %d: %+v, %v", i, snap, err)
		}
	}
	snap, err := s.ReplaceAll(ctx, snapshot(rows(40)...))
	if err != nil || snap.Merged {
		t.Fatalf("after %d merges: %+v, %v; want a replace", maxMerges, snap, err)
	}
	if score(t, s, "198.51.0.99") != 0 {
		t.Fatal("rows gone from the backend must go once the shrink is accepted")
	}
	// 40 is the new baseline: 30 is no shrink worth merging.
	if snap, err := s.ReplaceAll(ctx, snapshot(rows(30)...)); err != nil || snap.Merged {
		t.Fatalf("%+v, %v", snap, err)
	}
}
