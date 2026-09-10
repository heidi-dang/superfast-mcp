package oauth

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testCodeRecord() AuthorizationCodeRecord {
	return AuthorizationCodeRecord{
		ClientID:      "client-1",
		RedirectURI:   "https://chatgpt.com/connector_platform_oauth_redirect",
		CodeChallenge: strings.Repeat("c", 43),
		Resource:      "https://superfast.example.com/mcp",
		Scope:         "mcp",
		Subject:       "owner-subject",
		Email:         "owner@example.com",
	}
}

func testRefreshRecord() RefreshTokenRecord {
	return RefreshTokenRecord{
		ClientID: "client-1",
		Resource: "https://superfast.example.com/mcp",
		Scope:    "mcp",
		Subject:  "owner-subject",
		Email:    "owner@example.com",
	}
}

func TestAuthorizationCodesAreOneTimeAndPersistAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := OpenStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	code, err := store.IssueAuthorizationCode(testCodeRecord(), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = OpenStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	record, err := store.ConsumeAuthorizationCode(code)
	if err != nil {
		t.Fatal(err)
	}
	if record.ClientID != "client-1" || record.Subject != "owner-subject" {
		t.Fatalf("record=%+v", record)
	}
	if _, err := store.ConsumeAuthorizationCode(code); !errors.Is(err, ErrInvalidAuthorizationCode) {
		t.Fatalf("second consume err=%v, want ErrInvalidAuthorizationCode", err)
	}
}

func TestAuthorizationCodeExpires(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	base := time.Unix(1_800_000_000, 0)
	store.now = func() time.Time { return base }
	code, err := store.IssueAuthorizationCode(testCodeRecord(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return base.Add(2 * time.Minute) }
	if _, err := store.ConsumeAuthorizationCode(code); !errors.Is(err, ErrInvalidAuthorizationCode) {
		t.Fatalf("expired consume err=%v, want ErrInvalidAuthorizationCode", err)
	}
}

func TestRefreshTokenRotatesAndReuseRevokesFamily(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	expires := time.Now().Add(24 * time.Hour)
	first, firstRecord, err := store.IssueRefreshToken(testRefreshRecord(), expires)
	if err != nil {
		t.Fatal(err)
	}
	second, secondRecord, err := store.RotateRefreshToken(first, firstRecord.ClientID, firstRecord.Resource)
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatal("refresh token did not rotate")
	}
	if secondRecord.FamilyID == "" || secondRecord.FamilyID != firstRecord.FamilyID {
		t.Fatalf("family mismatch first=%q second=%q", firstRecord.FamilyID, secondRecord.FamilyID)
	}
	if _, _, err := store.RotateRefreshToken(first, firstRecord.ClientID, firstRecord.Resource); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("reuse err=%v, want ErrInvalidRefreshToken", err)
	}
	if _, _, err := store.RotateRefreshToken(second, secondRecord.ClientID, secondRecord.Resource); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("family token after reuse err=%v, want ErrInvalidRefreshToken", err)
	}
}

func TestRefreshRevocationRevokesFamily(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	first, record, err := store.IssueRefreshToken(testRefreshRecord(), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	second, secondRecord, err := store.RotateRefreshToken(first, record.ClientID, record.Resource)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeRefreshToken(second); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.RotateRefreshToken(second, secondRecord.ClientID, secondRecord.Resource); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("revoked family err=%v, want ErrInvalidRefreshToken", err)
	}
}

func TestStateDatabaseStoresHashesNotPlaintextTokens(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	code, err := store.IssueAuthorizationCode(testCodeRecord(), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	refresh, _, err := store.IssueRefreshToken(testRefreshRecord(), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var codeHash, codePayload string
	if err := store.db.QueryRow("SELECT code_hash, payload_json FROM oauth_authorization_codes LIMIT 1").Scan(&codeHash, &codePayload); err != nil {
		t.Fatal(err)
	}
	var refreshHash, refreshPayload string
	if err := store.db.QueryRow("SELECT token_hash, payload_json FROM oauth_refresh_tokens LIMIT 1").Scan(&refreshHash, &refreshPayload); err != nil {
		t.Fatal(err)
	}
	if codeHash == code || refreshHash == refresh {
		t.Fatal("database stored plaintext token in hash column")
	}
	if len(codeHash) != 64 || len(refreshHash) != 64 {
		t.Fatalf("unexpected hash lengths code=%d refresh=%d", len(codeHash), len(refreshHash))
	}
	if strings.Contains(codePayload, code) || strings.Contains(refreshPayload, refresh) {
		t.Fatal("database payload leaked plaintext token")
	}
}
