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
	// not put the stale row it read back into the cache.
	gen atomic.Uint64
}

func Open(path string, cacheSize int) (*Store, error) {
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=10000&_synchronous=NORMAL")
	if err != nil {
		return nil, err
	}
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
		if s.gen.Load() == gen {
			s.cache.Add(key, c)
		}
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
	s.gen.Add(1)
	s.cache.Remove(key)
	return nil
}

// ReplaceAll swaps the whole table for a snapshot. fill streams the snapshot
// into add. Rows Put while the snapshot loads stay if they are newer than
// the snapshot's row. IPs missing from the snapshot are removed. If fill
// fails, the current table is kept.
func (s *Store) ReplaceAll(ctx context.Context, fill func(add func(nfg.Score) error) error) (int, error) {
	s.mu.Lock()
	s.live = map[string]struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.live = nil
		s.mu.Unlock()
	}()

	if _, err := s.db.ExecContext(ctx, `CREATE TABLE ip_scores_next (ip TEXT PRIMARY KEY, score INTEGER, updated_at DATETIME)`); err != nil {
		return 0, err
	}
	n, err := s.loadNext(ctx, fill)
	if err == nil {
		err = s.swap(ctx)
	}
	if err != nil {
		_, _ = s.db.Exec(`DROP TABLE IF EXISTS ip_scores_next`)
		return 0, err
	}
	return n, nil
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

func (s *Store) swap(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit

	for ip := range s.live {
		var score int64
		var updated time.Time
		if err := tx.QueryRow(`SELECT score, updated_at FROM ip_scores WHERE ip = ?`, ip).Scan(&score, &updated); err != nil {
			return err
		}
		var snapUpdated sql.NullTime
		err := tx.QueryRow(`SELECT updated_at FROM ip_scores_next WHERE ip = ?`, ip).Scan(&snapUpdated)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if snapUpdated.Valid && snapUpdated.Time.After(updated) {
			continue
		}
		if _, err := tx.Exec(`INSERT OR REPLACE INTO ip_scores_next (ip, score, updated_at) VALUES (?, ?, ?)`, ip, score, updated); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DROP TABLE ip_scores; ALTER TABLE ip_scores_next RENAME TO ip_scores`); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.gen.Add(1)
	s.cache.Purge()
	return nil
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
	age := now.Sub(updated)
	if updated.IsZero() || age < 0 {
		age = 0
	}
	m := math.Max(math.Pow(0.5, age.Hours()/DecayHalfLife.Hours()), DecayFloor)
	return int32(math.Round(float64(score) * m))
}
