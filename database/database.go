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

type User struct {
	ID         int    `json:"id"`
	Username   string `json:"username"`
	PublicKey  string `json:"public_key"`
	IsAdmin    bool   `json:"is_admin"`
	IsApproved bool   `json:"is_approved"`
	CreatedAt  string `json:"created_at"`
	LastAuth   string `json:"last_auth"`
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
	if err := db.CreateUsersTable(); err != nil {
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

func (db *DB) CreateUsersTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		public_key TEXT NOT NULL,
		is_admin INTEGER DEFAULT 0,
		is_approved INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_auth DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	CREATE INDEX IF NOT EXISTS idx_users_public_key ON users(public_key);
	`
	_, err := db.conn.Exec(query)
	return err
}

func (db *DB) GetUserByUsernameAndPublicKey(username, pubKey string) (*User, error) {
	var user User
	var isAdmin, isApproved int
	err := db.conn.QueryRow(
		"SELECT id, username, public_key, is_admin, is_approved, created_at, last_auth FROM users WHERE username = ? AND public_key = ?",
		username, pubKey,
	).Scan(&user.ID, &user.Username, &user.PublicKey, &isAdmin, &isApproved, &user.CreatedAt, &user.LastAuth)
	if err != nil {
		return nil, err
	}
	user.IsAdmin = isAdmin == 1
	user.IsApproved = isApproved == 1
	return &user, nil
}

func (db *DB) GetUserByPublicKey(pubKey string) (*User, error) {
	var user User
	var isAdmin, isApproved int
	err := db.conn.QueryRow(
		"SELECT id, username, public_key, is_admin, is_approved, created_at, last_auth FROM users WHERE public_key = ?",
		pubKey,
	).Scan(&user.ID, &user.Username, &user.PublicKey, &isAdmin, &isApproved, &user.CreatedAt, &user.LastAuth)
	if err != nil {
		return nil, err
	}
	user.IsAdmin = isAdmin == 1
	user.IsApproved = isApproved == 1
	return &user, nil
}

func (db *DB) GetUsersByUsername(username string) ([]User, error) {
	rows, err := db.conn.Query(
		"SELECT id, username, public_key, is_admin, is_approved, created_at, last_auth FROM users WHERE username = ?",
		username,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var users []User
	for rows.Next() {
		var user User
		var isAdmin, isApproved int
		if err := rows.Scan(&user.ID, &user.Username, &user.PublicKey, &isAdmin, &isApproved, &user.CreatedAt, &user.LastAuth); err != nil {
			return nil, err
		}
		user.IsAdmin = isAdmin == 1
		user.IsApproved = isApproved == 1
		users = append(users, user)
	}
	return users, rows.Err()
}

func (db *DB) AddPublicKeyToUser(username, pubKey string) error {
	// This is a no-op now since we allow multiple keys per user
	// Just verify the user exists
	var count int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count)
	return err
}

func (db *DB) CreateUser(username, pubKey string, isAdmin bool) error {
	adminInt := 0
	approvedInt := 0
	if isAdmin {
		adminInt = 1
		approvedInt = 1 // Admins are auto-approved
	}
	_, err := db.conn.Exec(
		"INSERT INTO users (username, public_key, is_admin, is_approved) VALUES (?, ?, ?, ?)",
		username, pubKey, adminInt, approvedInt,
	)
	return err
}

func (db *DB) UpdateLastAuth(pubKey string) error {
	_, err := db.conn.Exec(
		"UPDATE users SET last_auth = CURRENT_TIMESTAMP WHERE public_key = ?",
		pubKey,
	)
	return err
}

func (db *DB) IsUsernameAvailable(username string) (bool, error) {
	var count int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count)
	if err != nil {
		return false, err
	}
	return count == 0, nil
}

func (db *DB) HasAnyUsers() (bool, error) {
	var count int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (db *DB) GetPendingUsers() ([]User, error) {
	rows, err := db.conn.Query(
		"SELECT id, username, public_key, is_admin, is_approved, created_at, last_auth FROM users WHERE is_approved = 0 ORDER BY created_at",
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var users []User
	for rows.Next() {
		var user User
		var isAdmin, isApproved int
		if err := rows.Scan(&user.ID, &user.Username, &user.PublicKey, &isAdmin, &isApproved, &user.CreatedAt, &user.LastAuth); err != nil {
			return nil, err
		}
		user.IsAdmin = isAdmin == 1
		user.IsApproved = isApproved == 1
		users = append(users, user)
	}
	return users, rows.Err()
}

func (db *DB) ApproveUser(username string) error {
	_, err := db.conn.Exec(
		"UPDATE users SET is_approved = 1 WHERE username = ?",
		username,
	)
	return err
}

func (db *DB) ApproveUserByID(userID int) error {
	_, err := db.conn.Exec(
		"UPDATE users SET is_approved = 1 WHERE id = ?",
		userID,
	)
	return err
}

func (db *DB) GetAllUsers() ([]User, error) {
	rows, err := db.conn.Query(
		"SELECT id, username, public_key, is_admin, is_approved, created_at, last_auth FROM users ORDER BY created_at",
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var users []User
	for rows.Next() {
		var user User
		var isAdmin, isApproved int
		if err := rows.Scan(&user.ID, &user.Username, &user.PublicKey, &isAdmin, &isApproved, &user.CreatedAt, &user.LastAuth); err != nil {
			return nil, err
		}
		user.IsAdmin = isAdmin == 1
		user.IsApproved = isApproved == 1
		users = append(users, user)
	}
	return users, rows.Err()
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
