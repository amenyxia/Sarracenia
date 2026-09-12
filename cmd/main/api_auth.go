package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
)

const authSchema = `
CREATE TABLE IF NOT EXISTS api_keys (
    id            INTEGER   PRIMARY KEY,
    key_hash      TEXT      NOT NULL UNIQUE,
    scopes        TEXT      NOT NULL,
    description   TEXT      NOT NULL
);
`

const masterKeyEnvVar = "sarr-master-key"

type contextKey string

const contextKeyPermissions = contextKey("permissions")

// Permissions holds the authentication info for a request.
type Permissions struct {
	ScopeSet map[string]struct{} // A set for O(1) lookups
}

// AuthAPI holds the dependencies for the authentication API handlers.
type AuthAPI struct {
	db     *sql.DB
	logger *slog.Logger
}

func setupAuthSchema(db *sql.DB) error {
	if _, err := db.Exec(authSchema); err != nil {
		return err
	}
	return nil
}

func NewAuthAPI(db *sql.DB, logger *slog.Logger) *AuthAPI {
	// Count keys in db. If 0, first-run key creation has to be done.
	var keyCount int
	_ = db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM api_keys").Scan(&keyCount)
	if keyCount == 0 {
		// First-run key creation. Check env var first, if not, random.
		masterKey := os.Getenv(masterKeyEnvVar)
		if masterKey == "" {
			masterKey, _ = generateAPIKey()
			logger.Warn("No API keys existed, generated master API key:", "key", masterKey)
		} else {
			logger.Warn("No API keys existed, using sarr-master-key API key:", "key", masterKey)
		}
		// Insert new master key into db.
		masterKeyHash := hashAPIKey(masterKey)
		_, err := db.ExecContext(context.Background(),
			`INSERT INTO api_keys (key_hash, description, scopes) VALUES (?, ?, ?)`,
			masterKeyHash, "Auto-Generated Master Key", "*")
		if err != nil {
			// This reasonably should never happen, but if it does, restart sarr?
			logger.Error("Failed to insert master API key", "error", err)
		}
	}

	return &AuthAPI{
		db:     db,
		logger: logger,
	}
}

// RegisterRoutes sets up the routing for all /api/auth endpoints on a standard http.ServeMux.
func (a *AuthAPI) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/auth/me", a.handleCheckMe)
	mux.HandleFunc("/api/auth/keys", a.handleKeys)
	mux.HandleFunc("/api/auth/keys/", a.handleKeyByID)
}

// APIKeyInfo is the structure returned when listing keys.
type APIKeyInfo struct {
	ID          int      `json:"id"`
	Scopes      []string `json:"scopes"`
	Description string   `json:"description"`
}

// CreateKeyRequest is the expected JSON body for creating a new key.
type CreateKeyRequest struct {
	Scopes      []string `json:"scopes"`
	Description string   `json:"description"`
}

// CreateKeyResponse is the JSON response after creating a key.
type CreateKeyResponse struct {
	ID     int      `json:"id"`
	RawKey string   `json:"raw_key"`
	Scopes []string `json:"scopes"`
}

// Authenticate is the core auth function. It checks for a valid key in the "sarr-auth" header.
// If authentication fails, it forwards the request to the tarpitHandler.
func (a *AuthAPI) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		apiKey := r.Header.Get("sarr-auth")
		if apiKey == "" {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		keyHash := hashAPIKey(apiKey)
		var scopesStr string
		err := a.db.QueryRowContext(r.Context(), "SELECT scopes FROM api_keys WHERE key_hash = ?", keyHash).Scan(&scopesStr)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			a.logger.Error("Authenticate failed to query API key", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		scopes := strings.Split(scopesStr, " ")
		scopeSet := make(map[string]struct{}, len(scopes))
		for _, s := range scopes {
			scopeSet[s] = struct{}{}
		}

		perms := &Permissions{ScopeSet: scopeSet}
		ctx := context.WithValue(r.Context(), contextKeyPermissions, perms)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *AuthAPI) handleKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.listKeys(w, r)
	case http.MethodPost:
		a.createKey(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (a *AuthAPI) handleKeyByID(w http.ResponseWriter, r *http.Request) {
	trimmedPath := strings.TrimPrefix(r.URL.Path, "/api/auth/keys/")
	idStr := strings.TrimSuffix(trimmedPath, "/") // Handle optional trailing slash

	id, err := strconv.Atoi(idStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid key ID format in URL")
		return
	}

	if r.Method == http.MethodDelete {
		a.deleteKey(w, r, id)
	} else {
		w.Header().Set("Allow", "DELETE")
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed for this key resource")
	}
}

func (a *AuthAPI) handleCheckMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	authCtx, ok := r.Context().Value(contextKeyPermissions).(*Permissions)
	if !ok {
		respondWithError(w, http.StatusUnauthorized, "Invalid or missing token")
		return
	}

	scopes := make([]string, 0, len(authCtx.ScopeSet))
	for s := range authCtx.ScopeSet {
		scopes = append(scopes, s)
	}

	respondWithJSON(w, http.StatusOK, map[string]any{
		"scopes": scopes,
	})
}

func (a *AuthAPI) listKeys(w http.ResponseWriter, r *http.Request) {
	if !hasScope(r, "auth:manage") {
		respondWithError(w, http.StatusForbidden, "Forbidden: requires 'auth:manage' scope")
		return
	}

	rows, err := a.db.QueryContext(r.Context(), `SELECT id, description, scopes FROM api_keys ORDER BY id`)
	if err != nil {
		a.logger.Error("Failed to query API keys", "error", err)
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Database query failed: %v", err))
		return
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	var keys []APIKeyInfo
	for rows.Next() {
		var key APIKeyInfo
		var scopesStr string
		if err = rows.Scan(&key.ID, &key.Description, &scopesStr); err != nil {
			a.logger.Error("Failed to scan API key row", "error", err)
			respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to process database results: %v", err))
			return
		}
		key.Scopes = strings.Split(scopesStr, " ")
		keys = append(keys, key)
	}
	respondWithJSON(w, http.StatusOK, keys)
}

func (a *AuthAPI) createKey(w http.ResponseWriter, r *http.Request) {

	if !hasScope(r, "auth:manage") {
		respondWithError(w, http.StatusForbidden, "Forbidden: requires 'auth:manage' scope")
		return
	}

	var req CreateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid JSON request body")
		return
	}

	rawKey, err := generateAPIKey()
	if err != nil {
		a.logger.Error("Failed to generate new API key", "error", err)
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Key generation failed: %v", err))
		return
	}
	keyHash := hashAPIKey(rawKey)

	scopesStr := strings.Join(req.Scopes, " ")

	var newID int
	err = a.db.QueryRowContext(r.Context(),
		`INSERT INTO api_keys (key_hash, description, scopes) VALUES (?, ?, ?) RETURNING id`,
		keyHash, req.Description, scopesStr).Scan(&newID)
	if err != nil {
		a.logger.Error("Failed to insert new API key", "error", err)
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to save new key: %v", err))
		return
	}

	response := CreateKeyResponse{
		ID:     newID,
		RawKey: rawKey,
		Scopes: strings.Split(scopesStr, " "),
	}
	respondWithJSON(w, http.StatusCreated, response)
}

func (a *AuthAPI) deleteKey(w http.ResponseWriter, r *http.Request, id int) {
	if !hasScope(r, "auth:manage") {
		respondWithError(w, http.StatusForbidden, "Forbidden: requires 'auth:manage' scope")
		return
	}

	if id == 1 {
		respondWithError(w, http.StatusBadRequest, "Cannot delete the primary master key (ID 1)")
		return
	}

	res, err := a.db.ExecContext(r.Context(), "DELETE FROM api_keys WHERE id = ?", id)
	if err != nil {
		a.logger.Error("Failed to delete API key", "id", id, "error", err)
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to delete key: %v", err))
		return
	}

	if rowsAffected, _ := res.RowsAffected(); rowsAffected == 0 {
		respondWithError(w, http.StatusNotFound, "Key not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// hasScope checks if the permission set in the request context includes a required scope.
func hasScope(r *http.Request, requiredScope string) bool {
	perms, ok := r.Context().Value(contextKeyPermissions).(*Permissions)
	if !ok {
		return false
	}

	if _, isMaster := perms.ScopeSet["*"]; isMaster {
		return true
	}

	_, has := perms.ScopeSet[requiredScope]
	return has
}

func generateAPIKey() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to read random bytes: %w", err)
	}
	return "sarr_" + hex.EncodeToString(bytes), nil
}

func hashAPIKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, map[string]string{"error": message})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if payload != nil {
		err := json.NewEncoder(w).Encode(payload)
		if err != nil {
			fmt.Printf("ERROR: Failed to encode JSON response: %v\n", err)
		}
	}
}
