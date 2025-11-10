package database

import (
	"database/sql"
	"embed"
	"log"
	"path/filepath"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

type ChannelType string

const (
	ChannelTypeText  ChannelType = "text"
	ChannelTypeVoice ChannelType = "voice"
)

type Channel struct {
	ID          int         `json:"id"`
	Name        string      `json:"name"`
	Type        ChannelType `json:"type"`
	Description string      `json:"description,omitempty"`
	CreatedAt   string      `json:"created_at"`
}

type DB struct {
	conn *sql.DB
}

func New(dataDir string) (*DB, error) {
	dbPath := filepath.Join(dataDir, "jakki.db")
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Exec("PRAGMA journal_mode = WAL"); err != nil {
		_ = conn.Close()
		return nil, err
	}
	db := &DB{conn: conn}
	if err := db.runMigrations(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	log.Printf("Database initialized at %s", dbPath)
	return db, nil
}

func (db *DB) Close() error {
	if db.conn != nil {
		return db.conn.Close()
	}
	return nil
}

func (db *DB) GetChannelByName(name string) (*Channel, error) {
	var ch Channel
	err := db.conn.QueryRow("SELECT id, name, type, description, created_at FROM channels WHERE name = ?", name).
		Scan(&ch.ID, &ch.Name, &ch.Type, &ch.Description, &ch.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &ch, nil
}

func (db *DB) GetAllChannelNames() ([]string, error) {
	rows, err := db.conn.Query("SELECT name FROM channels ORDER BY type, name")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

func (db *DB) GetAllChannels() ([]Channel, error) {
	rows, err := db.conn.Query("SELECT id, name, type, description, created_at FROM channels ORDER BY type, name")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var channels []Channel
	for rows.Next() {
		var ch Channel
		if err := rows.Scan(&ch.ID, &ch.Name, &ch.Type, &ch.Description, &ch.CreatedAt); err != nil {
			return nil, err
		}
		channels = append(channels, ch)
	}

	return channels, rows.Err()
}

func (db *DB) CreateChannel(name string, channelType ChannelType, description string) error {
	_, err := db.conn.Exec("INSERT INTO channels (name, type, description) VALUES (?, ?, ?)",
		name, channelType, description)
	return err
}

func (db *DB) DeleteChannel(name string) error {
	_, err := db.conn.Exec("DELETE FROM channels WHERE name = ?", name)
	return err
}

func (db *DB) runMigrations() error {
	driver, err := sqlite.WithInstance(db.conn, &sqlite.Config{})
	if err != nil {
		return err
	}
	sourceDriver, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	m, err := migrate.NewWithInstance("iofs", sourceDriver, "sqlite", driver)
	if err != nil {
		return err
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return err
	}
	version, _, _ := m.Version()
	log.Printf("Database migrated to version %d", version)
	return nil
}
