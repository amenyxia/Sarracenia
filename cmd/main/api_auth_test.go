package main

import (
	"bytes"
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// newAuthTestDB opens a fresh auth DB with the schema in a temp dir.
func newAuthTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := initDB(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("initDB failed: %v", err)
	}
	if err := setupAuthSchema(db); err != nil {
		t.Fatalf("setupAuthSchema failed: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// newTestLogger returns a logger that writes to a buffer so tests can assert on log output.
func newTestLogger(t *testing.T) (*slog.Logger, *bytes.Buffer) {
	t.Helper()
	buf := &bytes.Buffer{}
	return slog.New(slog.NewTextHandler(buf, nil)), buf
}

// seedKey inserts a key with the given raw key.
func seedKey(t *testing.T, db *sql.DB, rawKey string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO api_keys (key_hash, description, scopes) VALUES (?, ?, ?)`,
		hashAPIKey(rawKey), "seed key", "*"); err != nil {
		t.Fatalf("failed to seed key: %v", err)
	}
}

func TestBootstrapFromEnvVar(t *testing.T) {
	db := newAuthTestDB(t)
	t.Setenv(masterKeyEnvVar, "test-master-key-123")
	logger, _ := newTestLogger(t)
	_ = NewAuthAPI(db, logger)

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM api_keys").Scan(&count); err != nil {
		t.Fatalf("failed to count keys: %v", err)
	}
	if count != 1 {
		t.Fatalf("key count = %d, want 1", count)
	}
	var hash, scopes string
	if err := db.QueryRow("SELECT key_hash, scopes FROM api_keys").Scan(&hash, &scopes); err != nil {
		t.Fatalf("failed to query key: %v", err)
	}
	if hash != hashAPIKey("test-master-key-123") {
		t.Errorf("key_hash = %q, want hash of the env var value", hash)
	}
	if scopes != "*" {
		t.Errorf("scopes = %q, want %q", scopes, "*")
	}
}

func TestBootstrapGeneratesAndLogsKey(t *testing.T) {
	db := newAuthTestDB(t)
	logger, buf := newTestLogger(t)
	_ = NewAuthAPI(db, logger)

	// The warn line ends with `key=sarr_<64 hex>`; parse the raw key out of it.
	logs := buf.String()
	idx := strings.Index(logs, "key=sarr_")
	if idx == -1 {
		t.Fatalf("generated key not found in log output: %q", logs)
	}
	line := strings.SplitN(logs[idx:], "\n", 2)[0]
	rawKey := strings.SplitN(line, "key=", 2)[1] // already includes the sarr_ prefix

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM api_keys").Scan(&count); err != nil {
		t.Fatalf("failed to count keys: %v", err)
	}
	if count != 1 {
		t.Fatalf("key count = %d, want 1", count)
	}
	var hash string
	if err := db.QueryRow("SELECT key_hash FROM api_keys").Scan(&hash); err != nil {
		t.Fatalf("failed to query key: %v", err)
	}
	if hash != hashAPIKey(rawKey) {
		t.Errorf("key_hash = %q, want hash of the generated key", hash)
	}
}

func TestBootstrapSkippedWhenKeyExists(t *testing.T) {
	db := newAuthTestDB(t)
	seedKey(t, db, "existing-key-1")
	logger, buf := newTestLogger(t)
	_ = NewAuthAPI(db, logger)

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM api_keys").Scan(&count); err != nil {
		t.Fatalf("failed to count keys: %v", err)
	}
	if count != 1 {
		t.Fatalf("key count = %d, want 1", count)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no log output when a key exists, got: %q", buf.String())
	}
}

func TestFirstRunWindowClosedWithoutKeys(t *testing.T) {
	db := newAuthTestDB(t)
	logger, _ := newTestLogger(t)
	api := &AuthAPI{db: db, logger: logger}

	var called bool
	handler := api.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if called {
		t.Error("next handler was reached without any API keys")
	}
}

func TestAuthStillRequiredAfterKeyExists(t *testing.T) {
	db := newAuthTestDB(t)
	seedKey(t, db, "existing-key-1")
	logger, _ := newTestLogger(t)
	api := &AuthAPI{db: db, logger: logger}

	var gotScopes map[string]struct{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, ok := r.Context().Value(contextKeyPermissions).(*Permissions); ok {
			gotScopes = p.ScopeSet
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
	handler := api.Authenticate(next)

	// A wrong key must still be rejected.
	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.Header.Set("sarr-auth", "wrong-key")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong key: status = %d, want %d", w.Code, http.StatusUnauthorized)
	}

	// The correct key must pass and carry the master scope in context.
	req = httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.Header.Set("sarr-auth", "existing-key-1")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("correct key: status = %d, want %d", w.Code, http.StatusOK)
	}
	if _, ok := gotScopes["*"]; !ok {
		t.Errorf("master scope %q missing from request context", "*")
	}
}

func TestCreateKeyGetsRequestedScopes(t *testing.T) {
	db := newAuthTestDB(t)
	seedKey(t, db, "master-key") // bootstrap already created the master key
	logger, _ := newTestLogger(t)
	api := &AuthAPI{db: db, logger: logger}

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	body := `{"scopes": ["stats:read"], "description": "stats key"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/keys", strings.NewReader(body))
	// Master permissions so the handler's hasScope check passes.
	ctx := context.WithValue(req.Context(), contextKeyPermissions, &Permissions{ScopeSet: map[string]struct{}{"*": {}}})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusCreated)
	}

	// The new key (id 2) gets the requested scopes, not the master scope.
	var scopes string
	if err := db.QueryRow("SELECT scopes FROM api_keys WHERE id = 2").Scan(&scopes); err != nil {
		t.Fatalf("failed to query new key scopes: %v", err)
	}
	if scopes != "stats:read" {
		t.Errorf("scopes = %q, want %q", scopes, "stats:read")
	}
}
