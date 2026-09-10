package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrInvalidAuthorizationCode = errors.New("invalid authorization code")
	ErrInvalidRefreshToken      = errors.New("invalid refresh token")
)

type AuthorizationCodeRecord struct {
	ClientID      string `json:"client_id"`
	RedirectURI   string `json:"redirect_uri"`
	CodeChallenge string `json:"code_challenge"`
	Resource      string `json:"resource"`
	Scope         string `json:"scope"`
	Subject       string `json:"subject"`
	Email         string `json:"email,omitempty"`
}

type RefreshTokenRecord struct {
	ClientID  string `json:"client_id"`
	Resource  string `json:"resource"`
	Scope     string `json:"scope"`
	Subject   string `json:"subject"`
	Email     string `json:"email,omitempty"`
	FamilyID  string `json:"family_id"`
	ExpiresAt int64  `json:"expires_at"`
}

type StateStore struct {
	db  *sql.DB
	now func() time.Time
}

func OpenStateStore(path string) (*StateStore, error) {
	if path == "" {
		return nil, errors.New("oauth state database path is required")
	}
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, fmt.Errorf("create oauth state directory: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open oauth state database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &StateStore{db: db, now: time.Now}
	if err := store.initialize(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *StateStore) initialize() error {
	statements := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=FULL",
		"PRAGMA foreign_keys=ON",
		`CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
			code_hash TEXT PRIMARY KEY,
			payload_json TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL
		)`,
		"CREATE INDEX IF NOT EXISTS oauth_authorization_codes_expiry ON oauth_authorization_codes(expires_at)",
		`CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
			token_hash TEXT PRIMARY KEY,
			family_id TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			used_at INTEGER,
			revoked_at INTEGER
		)`,
		"CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_expiry ON oauth_refresh_tokens(expires_at)",
		"CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_family ON oauth_refresh_tokens(family_id)",
	}
	for _, statement := range statements {
		if _, err := s.db.Exec(statement); err != nil {
			return fmt.Errorf("initialize oauth state database: %w", err)
		}
	}
	return nil
}

func (s *StateStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *StateStore) prune(now time.Time) error {
	nowMS := now.UnixMilli()
	if _, err := s.db.Exec("DELETE FROM oauth_authorization_codes WHERE expires_at <= ?", nowMS); err != nil {
		return err
	}
	if _, err := s.db.Exec("DELETE FROM oauth_refresh_tokens WHERE expires_at <= ?", nowMS); err != nil {
		return err
	}
	return nil
}

func (s *StateStore) IssueAuthorizationCode(record AuthorizationCodeRecord, ttl time.Duration) (string, error) {
	now := s.now()
	if err := s.prune(now); err != nil {
		return "", fmt.Errorf("prune oauth state: %w", err)
	}
	code, err := randomOpaque("sfc_code", 32)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("encode authorization code state: %w", err)
	}
	if _, err := s.db.Exec(
		"INSERT INTO oauth_authorization_codes(code_hash, payload_json, expires_at, created_at) VALUES (?, ?, ?, ?)",
		hashOpaque(code), string(payload), now.Add(ttl).UnixMilli(), now.UnixMilli(),
	); err != nil {
		return "", fmt.Errorf("store authorization code: %w", err)
	}
	return code, nil
}

func (s *StateStore) ConsumeAuthorizationCode(code string) (*AuthorizationCodeRecord, error) {
	if code == "" {
		return nil, ErrInvalidAuthorizationCode
	}
	now := s.now()
	if err := s.prune(now); err != nil {
		return nil, fmt.Errorf("prune oauth state: %w", err)
	}
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return nil, fmt.Errorf("acquire oauth state connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		return nil, fmt.Errorf("begin authorization-code transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	var payload string
	var expiresAt int64
	err = conn.QueryRowContext(context.Background(),
		"SELECT payload_json, expires_at FROM oauth_authorization_codes WHERE code_hash = ?", hashOpaque(code),
	).Scan(&payload, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) || expiresAt <= now.UnixMilli() {
		return nil, ErrInvalidAuthorizationCode
	}
	if err != nil {
		return nil, fmt.Errorf("read authorization code: %w", err)
	}
	if _, err := conn.ExecContext(context.Background(), "DELETE FROM oauth_authorization_codes WHERE code_hash = ?", hashOpaque(code)); err != nil {
		return nil, fmt.Errorf("consume authorization code: %w", err)
	}
	var record AuthorizationCodeRecord
	if err := json.Unmarshal([]byte(payload), &record); err != nil {
		return nil, ErrInvalidAuthorizationCode
	}
	if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
		return nil, fmt.Errorf("commit authorization-code transaction: %w", err)
	}
	committed = true
	return &record, nil
}

func (s *StateStore) IssueRefreshToken(record RefreshTokenRecord, expiresAt time.Time) (string, RefreshTokenRecord, error) {
	now := s.now()
	if err := s.prune(now); err != nil {
		return "", RefreshTokenRecord{}, fmt.Errorf("prune oauth state: %w", err)
	}
	if record.FamilyID == "" {
		familyID, err := randomOpaque("sfc_family", 16)
		if err != nil {
			return "", RefreshTokenRecord{}, err
		}
		record.FamilyID = familyID
	}
	record.ExpiresAt = expiresAt.UnixMilli()
	token, err := randomOpaque("sfc_refresh", 32)
	if err != nil {
		return "", RefreshTokenRecord{}, err
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return "", RefreshTokenRecord{}, fmt.Errorf("encode refresh state: %w", err)
	}
	if _, err := s.db.Exec(
		"INSERT INTO oauth_refresh_tokens(token_hash, family_id, payload_json, expires_at, created_at, used_at, revoked_at) VALUES (?, ?, ?, ?, ?, NULL, NULL)",
		hashOpaque(token), record.FamilyID, string(payload), record.ExpiresAt, now.UnixMilli(),
	); err != nil {
		return "", RefreshTokenRecord{}, fmt.Errorf("store refresh token: %w", err)
	}
	return token, record, nil
}

func (s *StateStore) RotateRefreshToken(token, clientID, resource string) (string, RefreshTokenRecord, error) {
	if token == "" || clientID == "" || resource == "" {
		return "", RefreshTokenRecord{}, ErrInvalidRefreshToken
	}
	now := s.now()
	if err := s.prune(now); err != nil {
		return "", RefreshTokenRecord{}, fmt.Errorf("prune oauth state: %w", err)
	}
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return "", RefreshTokenRecord{}, fmt.Errorf("acquire oauth state connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return "", RefreshTokenRecord{}, fmt.Errorf("begin refresh transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	var familyID, payload string
	var expiresAt int64
	var usedAt, revokedAt sql.NullInt64
	err = conn.QueryRowContext(ctx,
		"SELECT family_id, payload_json, expires_at, used_at, revoked_at FROM oauth_refresh_tokens WHERE token_hash = ?",
		hashOpaque(token),
	).Scan(&familyID, &payload, &expiresAt, &usedAt, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", RefreshTokenRecord{}, ErrInvalidRefreshToken
	}
	if err != nil {
		return "", RefreshTokenRecord{}, fmt.Errorf("read refresh token: %w", err)
	}
	if expiresAt <= now.UnixMilli() || revokedAt.Valid {
		return "", RefreshTokenRecord{}, ErrInvalidRefreshToken
	}
	if usedAt.Valid {
		if _, err := conn.ExecContext(ctx,
			"UPDATE oauth_refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL",
			now.UnixMilli(), familyID,
		); err != nil {
			return "", RefreshTokenRecord{}, fmt.Errorf("revoke reused refresh family: %w", err)
		}
		if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
			return "", RefreshTokenRecord{}, fmt.Errorf("commit refresh reuse revocation: %w", err)
		}
		committed = true
		return "", RefreshTokenRecord{}, ErrInvalidRefreshToken
	}

	var record RefreshTokenRecord
	if err := json.Unmarshal([]byte(payload), &record); err != nil {
		return "", RefreshTokenRecord{}, ErrInvalidRefreshToken
	}
	if record.ClientID != clientID || record.Resource != resource || record.FamilyID != familyID {
		return "", RefreshTokenRecord{}, ErrInvalidRefreshToken
	}
	if _, err := conn.ExecContext(ctx, "UPDATE oauth_refresh_tokens SET used_at = ? WHERE token_hash = ?", now.UnixMilli(), hashOpaque(token)); err != nil {
		return "", RefreshTokenRecord{}, fmt.Errorf("mark refresh token used: %w", err)
	}
	replacement, err := randomOpaque("sfc_refresh", 32)
	if err != nil {
		return "", RefreshTokenRecord{}, err
	}
	if _, err := conn.ExecContext(ctx,
		"INSERT INTO oauth_refresh_tokens(token_hash, family_id, payload_json, expires_at, created_at, used_at, revoked_at) VALUES (?, ?, ?, ?, ?, NULL, NULL)",
		hashOpaque(replacement), record.FamilyID, payload, record.ExpiresAt, now.UnixMilli(),
	); err != nil {
		return "", RefreshTokenRecord{}, fmt.Errorf("store rotated refresh token: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return "", RefreshTokenRecord{}, fmt.Errorf("commit refresh rotation: %w", err)
	}
	committed = true
	return replacement, record, nil
}

func (s *StateStore) RevokeRefreshToken(token string) error {
	if token == "" {
		return nil
	}
	var familyID string
	err := s.db.QueryRow("SELECT family_id FROM oauth_refresh_tokens WHERE token_hash = ?", hashOpaque(token)).Scan(&familyID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read refresh family: %w", err)
	}
	if _, err := s.db.Exec(
		"UPDATE oauth_refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL",
		s.now().UnixMilli(), familyID,
	); err != nil {
		return fmt.Errorf("revoke refresh family: %w", err)
	}
	return nil
}

func randomOpaque(prefix string, size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate oauth token: %w", err)
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(buf), nil
}

func hashOpaque(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
