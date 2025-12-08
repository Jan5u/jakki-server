package database

import (
	"embed"
	"log"
	"path/filepath"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jmoiron/sqlx"
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
	ID          int         `db:"id" json:"id"`
	Name        string      `db:"name" json:"name"`
	Type        ChannelType `db:"type" json:"type"`
	Description string      `db:"description" json:"description,omitempty"`
	CreatedAt   string      `db:"created_at" json:"created_at"`
}

type User struct {
	ID         int    `db:"id" json:"id"`
	Username   string `db:"username" json:"username"`
	PublicKey  string `db:"public_key" json:"public_key"`
	IsAdmin    bool   `db:"is_admin" json:"is_admin"`
	IsApproved bool   `db:"is_approved" json:"is_approved"`
	CreatedAt  string `db:"created_at" json:"created_at"`
	LastAuth   string `db:"last_auth" json:"last_auth"`
}

type rawUser struct {
	ID         int    `db:"id"`
	Username   string `db:"username"`
	PublicKey  string `db:"public_key"`
	IsAdmin    int    `db:"is_admin"`
	IsApproved int    `db:"is_approved"`
	CreatedAt  string `db:"created_at"`
	LastAuth   string `db:"last_auth"`
}

func (r *rawUser) toUser() *User {
	return &User{
		ID:         r.ID,
		Username:   r.Username,
		PublicKey:  r.PublicKey,
		IsAdmin:    r.IsAdmin == 1,
		IsApproved: r.IsApproved == 1,
		CreatedAt:  r.CreatedAt,
		LastAuth:   r.LastAuth,
	}
}

func rawUsersToUsers(rawUsers []rawUser) []User {
	users := make([]User, len(rawUsers))
	for i, ru := range rawUsers {
		users[i] = *ru.toUser()
	}
	return users
}

type DB struct {
	conn *sqlx.DB
}

func New(dataDir string) (*DB, error) {
	dbPath := filepath.Join(dataDir, "jakki.db")
	conn, err := sqlx.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	conn.MapperFunc(func(s string) string { return s })
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
	err := db.conn.Get(&ch, "SELECT * FROM channels WHERE name = ?", name)
	if err != nil {
		return nil, err
	}
	return &ch, nil
}

func (db *DB) GetAllChannelNames() ([]string, error) {
	var names []string
	err := db.conn.Select(&names, "SELECT name FROM channels ORDER BY type, name")
	return names, err
}

func (db *DB) GetAllChannels() ([]Channel, error) {
	var channels []Channel
	err := db.conn.Select(&channels, "SELECT * FROM channels ORDER BY type, name")
	return channels, err
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

func (db *DB) GetUserByUsernameAndPublicKey(username, pubKey string) (*User, error) {
	var raw rawUser
	err := db.conn.Get(&raw, "SELECT * FROM users WHERE username = ? AND public_key = ?", username, pubKey)
	if err != nil {
		return nil, err
	}
	return raw.toUser(), nil
}

func (db *DB) GetUserByPublicKey(pubKey string) (*User, error) {
	var raw rawUser
	err := db.conn.Get(&raw, "SELECT * FROM users WHERE public_key = ?", pubKey)
	if err != nil {
		return nil, err
	}
	return raw.toUser(), nil
}

func (db *DB) GetUsersByUsername(username string) ([]User, error) {
	var rawUsers []rawUser
	err := db.conn.Select(&rawUsers, "SELECT * FROM users WHERE username = ?", username)
	if err != nil {
		return nil, err
	}
	return rawUsersToUsers(rawUsers), nil
}

func (db *DB) AddPublicKeyToUser(username, pubKey string) error {
	var count int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count)
	return err
}

func (db *DB) CreateUser(username, pubKey string, isAdmin bool) error {
	adminInt := 0
	approvedInt := 0
	if isAdmin {
		adminInt = 1
		approvedInt = 1
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
	var rawUsers []rawUser
	err := db.conn.Select(&rawUsers, "SELECT * FROM users WHERE is_approved = 0 ORDER BY created_at")
	if err != nil {
		return nil, err
	}
	return rawUsersToUsers(rawUsers), nil
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
	var rawUsers []rawUser
	err := db.conn.Select(&rawUsers, "SELECT * FROM users ORDER BY created_at")
	if err != nil {
		return nil, err
	}
	return rawUsersToUsers(rawUsers), nil
}

func (db *DB) runMigrations() error {
	driver, err := sqlite.WithInstance(db.conn.DB, &sqlite.Config{})
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
