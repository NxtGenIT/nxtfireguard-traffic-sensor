// Package scores keeps the NFG score of every IP the license can see in a
// local SQLite database, so lookups never wait on the network.
package scores

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NxtGenIT/nxtfireguard-traffic-sensor/internal/nfg"
	"github.com/hashicorp/golang-lru/v2/expirable"
	_ "github.com/mattn/go-sqlite3" // database/sql driver "sqlite3"
)

// Scores lose half their weight every DecayHalfLife without an update, but
// never drop below DecayFloor of the original value.
const (
	DecayHalfLife = 72 * time.Hour
	DecayFloor    = 0.3
)

// cacheTTL bounds how long a looked-up score is served from memory.
const cacheTTL = 5 * time.Minute

// snapshotChunk rows are written per transaction while loading a snapshot.
const snapshotChunk = 5000

type cached struct {
	score   int32
	updated time.Time
}

type Store struct {
	db    *sql.DB
	cache *expirable.LRU[string, cached]
	now   func() time.Time

	// mu serialises live writes with the snapshot swap. live records the IPs
	// written while a snapshot is loading; it is nil otherwise.
	mu   sync.Mutex
	live map[string]struct{}

	// gen changes on every write, so a lookup that raced with a write does
	// not put the stale row it read back into the cache. cacheMu makes
	// "gen unchanged, so add" and "bump gen, then evict" atomic with each
	// other; without it a lookup could check gen, lose the CPU to a write
	// that bumps gen and evicts, and then add its stale row.
	gen     atomic.Uint64
	cacheMu sync.Mutex
}

// ErrEmptySnapshot is returned when the backend sends no scores while the
// sensor has some. That is a backend fault (an empty cache, a license
// mix-up), and keeping the old scores is safer than blocking nothing.
var ErrEmptySnapshot = errors.New("score snapshot is empty, keeping the current scores")

// Snapshot is the outcome of ReplaceAll.
type Snapshot struct {
	Rows int // rows in the snapshot
	// Merged is set when the snapshot had less than half the rows of the
	// last snapshot that replaced the table. Then the old rows it lacks are
	// kept instead of removed: a truncated download must not silently
	// unblock half the threats. After maxMerges merges in a row the
	// shrink is taken as real and the next snapshot replaces the table.
	Merged bool
}

// maxMerges bounds how many small snapshots in a row are merged.
const maxMerges = 3

// baselineKey stores, in sensor_state, the size of the last snapshot that
// replaced the table and how many merges followed it.
const baselineKey = "score_snapshot"

type baseline struct {
	Rows   int `json:"rows"`
	Merges int `json:"merges"`
}

func Open(path string, cacheSize int) (*Store, error) {
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=10000&_synchronous=NORMAL&_txlock=immediate")
	if err != nil {
		return nil, err
	}
	// _txlock=immediate: write transactions take the write lock at BEGIN,
	// so two of them wait on busy_timeout instead of one failing with
	// "database is locked" when it upgrades from read to write.
	db.SetMaxOpenConns(4)
	// ip_scores keeps the schema of earlier releases so existing volumes
	// load without migration.
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS ip_scores (
			ip TEXT PRIMARY KEY,
			score INTEGER,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS sensor_state (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);
		DROP TABLE IF EXISTS ip_scores_next;
	`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return &Store{
		db:    db,
		cache: expirable.NewLRU[string, cached](cacheSize, nil, cacheTTL),
		now:   time.Now,
	}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Score returns the decayed score of ip, or 0 if the backend has none.
func (s *Store) Score(ip netip.Addr) (int32, error) {
	key := ip.String()
	c, ok := s.cache.Get(key)
	if !ok {
		gen := s.gen.Load()
		var score sql.NullInt64
		var updated sql.NullTime
		err := s.db.QueryRow(`SELECT score, updated_at FROM ip_scores WHERE ip = ?`, key).Scan(&score, &updated)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return 0, err
		default:
			c = cached{score: int32(score.Int64), updated: updated.Time}
		}
		// Unknown IPs are cached too: most traffic has no score.
		s.cacheMu.Lock()
		if s.gen.Load() == gen {
			s.cache.Add(key, c)
		}
		s.cacheMu.Unlock()
	}
	return Decay(c.score, c.updated, s.now()), nil
}

// Put stores a live score update.
func (s *Store) Put(sc nfg.Score) error {
	key, at := s.normalize(sc)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec(`INSERT OR REPLACE INTO ip_scores (ip, score, updated_at) VALUES (?, ?, ?)`, key, sc.Score, at); err != nil {
		return err
	}
	if s.live != nil {
		s.live[key] = struct{}{}
	}
	s.invalidate(func() { s.cache.Remove(key) })
	return nil
}

// ReplaceAll swaps the whole table for a snapshot. fill streams the snapshot
// into add. Rows Put while the snapshot loads stay if they are newer than
// the snapshot's row. IPs missing from the snapshot are removed, unless the
// snapshot is suspiciously small (see Snapshot.Merged). If fill fails or
// the snapshot is empty, the current table is kept.
func (s *Store) ReplaceAll(ctx context.Context, fill func(add func(nfg.Score) error) error) (Snapshot, error) {
	s.mu.Lock()
	s.live = map[string]struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.live = nil
		s.mu.Unlock()
	}()

	if _, err := s.db.ExecContext(ctx, `CREATE TABLE ip_scores_next (ip TEXT PRIMARY KEY, score INTEGER, updated_at DATETIME)`); err != nil {
		return Snapshot{}, err
	}
	snap := Snapshot{}
	var err error
	snap.Rows, err = s.loadNext(ctx, fill)
	if err == nil {
		snap.Merged, err = s.swap(ctx, snap.Rows)
	}
	if err != nil {
		_, _ = s.db.Exec(`DROP TABLE IF EXISTS ip_scores_next`)
		return Snapshot{}, err
	}
	return snap, nil
}

// loadNext buffers rows and writes each full chunk in its own short
// transaction, so the write lock is never held while waiting on the network.
func (s *Store) loadNext(ctx context.Context, fill func(add func(nfg.Score) error) error) (int, error) {
	type row struct {
		ip    string
		score int32
		at    time.Time
	}
	buf := make([]row, 0, snapshotChunk)
	n := 0
	flush := func() error {
		if len(buf) == 0 {
			return nil
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback() //nolint:errcheck // no-op after commit
		stmt, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO ip_scores_next (ip, score, updated_at) VALUES (?, ?, ?)`)
		if err != nil {
			return err
		}
		for _, r := range buf {
			if _, err := stmt.ExecContext(ctx, r.ip, r.score, r.at); err != nil {
				return err
			}
		}
		buf = buf[:0]
		return tx.Commit()
	}
	err := fill(func(sc nfg.Score) error {
		key, at := s.normalize(sc)
		buf = append(buf, row{key, sc.Score, at})
		n++
		if len(buf) == snapshotChunk {
			return flush()
		}
		return nil
	})
	if err == nil {
		err = flush()
	}
	return n, err
}

func (s *Store) swap(ctx context.Context, rows int) (merged bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit

	var have int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM ip_scores`).Scan(&have); err != nil {
		return false, err
	}
	if rows == 0 && have > 0 {
		return false, ErrEmptySnapshot
	}
	// Compare with the last replacing snapshot, not with COUNT(*): merged
	// rows must not make every later snapshot look small. Without a
	// baseline (first run, or a volume from an earlier release that never
	// removed rows) the snapshot replaces the table.
	var base baseline
	var raw string
	switch err := tx.QueryRow(`SELECT value FROM sensor_state WHERE key = ?`, baselineKey).Scan(&raw); {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return false, err
	default:
		_ = json.Unmarshal([]byte(raw), &base) // unreadable: no baseline
	}
	if rows < base.Rows/2 && base.Merges < maxMerges {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO ip_scores_next (ip, score, updated_at) SELECT ip, score, updated_at FROM ip_scores`); err != nil {
			return false, err
		}
		merged = true
		base.Merges++
	} else {
		base = baseline{Rows: rows}
	}
	b, _ := json.Marshal(base)
	if _, err := tx.Exec(`INSERT OR REPLACE INTO sensor_state (key, value) VALUES (?, ?)`, baselineKey, string(b)); err != nil {
		return false, err
	}

	for ip := range s.live {
		var score int64
		var updated time.Time
		if err := tx.QueryRow(`SELECT score, updated_at FROM ip_scores WHERE ip = ?`, ip).Scan(&score, &updated); err != nil {
			return false, err
		}
		var snapUpdated sql.NullTime
		err := tx.QueryRow(`SELECT updated_at FROM ip_scores_next WHERE ip = ?`, ip).Scan(&snapUpdated)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return false, err
		}
		if snapUpdated.Valid && snapUpdated.Time.After(updated) {
			continue
		}
		if _, err := tx.Exec(`INSERT OR REPLACE INTO ip_scores_next (ip, score, updated_at) VALUES (?, ?, ?)`, ip, score, updated); err != nil {
			return false, err
		}
	}
	if _, err := tx.Exec(`DROP TABLE ip_scores; ALTER TABLE ip_scores_next RENAME TO ip_scores`); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	s.invalidate(s.cache.Purge)
	return merged, nil
}

func (s *Store) invalidate(evict func()) {
	s.cacheMu.Lock()
	s.gen.Add(1)
	evict()
	s.cacheMu.Unlock()
}

// normalize keys rows by the canonical text form of the address, which is
// what lookups use, and dates rows without a timestamp to now.
func (s *Store) normalize(sc nfg.Score) (string, time.Time) {
	key := sc.IP
	if a, err := netip.ParseAddr(sc.IP); err == nil {
		key = a.Unmap().String()
	}
	at := sc.LastUpdated
	if at.IsZero() {
		at = s.now()
	}
	return key, at.UTC()
}

// LoadState decodes the value saved under key into v. It reports false if
// nothing was saved.
func (s *Store) LoadState(key string, v any) (bool, error) {
	var raw string
	err := s.db.QueryRow(`SELECT value FROM sensor_state WHERE key = ?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal([]byte(raw), v)
}

func (s *Store) SaveState(key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT OR REPLACE INTO sensor_state (key, value) VALUES (?, ?)`, key, string(raw))
	return err
}

// Decay weighs score by the time since it was last updated.
func Decay(score int32, updated, now time.Time) int32 {
	if score == 0 {
		return 0
	}
	// Earlier releases stored live updates without a time; those rows were
	// served at the floor and still are. New rows always carry a time.
	if updated.IsZero() || updated.Year() < 2000 {
		return int32(math.Round(float64(score) * DecayFloor))
	}
	age := max(now.Sub(updated), 0) // clock skew must not inflate a score
	m := math.Max(math.Pow(0.5, age.Hours()/DecayHalfLife.Hours()), DecayFloor)
	return int32(math.Round(float64(score) * m))
}
