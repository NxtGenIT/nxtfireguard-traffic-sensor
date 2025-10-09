package sqlite

import (
	"database/sql"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
)

var (
	db     *sql.DB
	dbOnce sync.Once
)

// initializes the database and connection pool
func Init(dbPath string) error {
	var err error
	dbOnce.Do(func() {
		zap.L().Info("Initializing SQLite database", zap.String("dbPath", dbPath))

		db, err = sql.Open("sqlite3", dbPath)
		if err != nil {
			zap.L().Error("Failed to open SQLite database", zap.String("dbPath", dbPath), zap.Error(err))
			return
		}

		db.SetMaxOpenConns(1) // SQLite is not fully concurrent — 1 is safest
		db.SetMaxIdleConns(1)
		db.SetConnMaxLifetime(1 * time.Hour) // Rotate connections

		zap.L().Info("Setting up SQLite connection pool",
			zap.Int("maxOpenConns", 1),
			zap.Int("maxIdleConns", 1),
			zap.Duration("connMaxLifetime", 1*time.Hour),
		)

		// Initialize schema
		err = bootstrapSchema()
		if err != nil {
			zap.L().Error("Failed to initialize SQLite schema", zap.Error(err))
			_ = db.Close()
		} else {
			zap.L().Info("SQLite schema initialized successfully")
		}
	})

	if err != nil {
		zap.L().Error("SQLite initialization failed", zap.Error(err))
	} else {
		zap.L().Info("SQLite initialization complete")
	}

	return err
}

func GetDB() *sql.DB {
	return db
}

func bootstrapSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS ip_scores (
		ip TEXT PRIMARY KEY,
		score INTEGER,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`
	//zap.L().Debug("Bootstrapping SQLite schema")
	_, err := db.Exec(schema)
	if err != nil {
		zap.L().Error("Failed to execute schema statement", zap.Error(err))
	}
	return err
}
