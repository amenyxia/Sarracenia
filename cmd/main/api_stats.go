package main

import (
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"
)

const statsSchema = `
CREATE TABLE IF NOT EXISTS stats_ip (
    ip_address    TEXT PRIMARY KEY,
    total_hits    INTEGER NOT NULL DEFAULT 1,
    first_seen    DATETIME NOT NULL,
    last_seen     DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS stats_user_agent (
    user_agent    TEXT PRIMARY KEY,
    total_hits    INTEGER NOT NULL DEFAULT 1,
    first_seen    DATETIME NOT NULL,
    last_seen     DATETIME NOT NULL
);
`

// RequestMetrics is the data structure returned for a single request.
type RequestMetrics struct {
	IPAddress        string        `json:"ip_address"`
	UserAgent        string        `json:"user_agent"`
	IPTotalHits      int           `json:"ip_total_hits"`
	UATotalHits      int           `json:"ua_total_hits"`
	TimeSinceIPFirst time.Duration `json:"time_since_ip_first_seen"`
	TimeSinceUAFirst time.Duration `json:"time_since_ua_first_seen"`
}

// GlobalStatsSummary provides a high-level overview of all collected stats.
type GlobalStatsSummary struct {
	TotalRequests    int64 `json:"total_requests"`
	UniqueIPs        int64 `json:"unique_ips"`
	UniqueUserAgents int64 `json:"unique_user_agents"`
}

// IPStats holds statistics for a single IP address.
type IPStats struct {
	TotalHits int
	FirstSeen time.Time
	LastSeen  time.Time
}

// UAStats holds statistics for a single user agent.
type UAStats struct {
	TotalHits int
	FirstSeen time.Time
	LastSeen  time.Time
}

// MetricsCache holds statistics in-memory for faster access and no db locking
type MetricsCache struct {
	mu             sync.RWMutex
	ipStats        map[string]*IPStats
	uaStats        map[string]*UAStats
	db             *sql.DB
	logger         *slog.Logger
	config         *StatsConfig
	lastSyncTime   time.Time
	syncInProgress bool
	syncMutex      sync.Mutex // Separate mutex for sync operations to avoid blocking cache operations
}

// StatsAPI holds the dependencies for the statistics handlers.
type StatsAPI struct {
	cache  *MetricsCache
	db     *sql.DB
	logger *slog.Logger
}

func setupStatsSchema(db *sql.DB) error {
	_, err := db.Exec(statsSchema)
	return err
}

func NewStatsAPI(db *sql.DB, logger *slog.Logger) *StatsAPI {
	return &StatsAPI{
		db:     db,
		logger: logger,
	}
}

// InitializeCache initializes the in-memory cache (no background sync).
func (s *StatsAPI) InitializeCache(config *StatsConfig) error {
	// Create the cache with initial data loaded from DB
	cache := &MetricsCache{
		ipStats:        make(map[string]*IPStats),
		uaStats:        make(map[string]*UAStats),
		db:             s.db,
		logger:         s.logger,
		config:         config,
		lastSyncTime:   time.Now(),
		syncInProgress: false,
	}

	// Load existing data from database
	if err := cache.loadFromDB(); err != nil {
		return fmt.Errorf("failed to load stats from database: %w", err)
	}

	s.cache = cache
	return nil
}

func (s *StatsAPI) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/stats/summary", s.handleSummary)
	mux.HandleFunc("/api/stats/top_ips", s.handleTopIPs)
	mux.HandleFunc("/api/stats/top_user_agents", s.handleTopUserAgents)
	mux.HandleFunc("/api/stats/all", s.handleResetAll)
}

// LogAndGetMetrics is the core function called by the tarpit handler.
// It logs the request and returns up-to-date metrics using the in-memory cache.
func (s *StatsAPI) LogAndGetMetrics(r *http.Request, ip string) (*RequestMetrics, error) {
	ua := r.UserAgent()
	now := time.Now()

	// Get metrics and also trigger sync if needed
	metrics := s.cache.GetOrIncrementMetrics(ip, ua, now)

	// Check if sync is needed after updating metrics
	go s.cache.syncToDBIfDue()

	return metrics, nil
}

// GetOrIncrementMetrics gets the current stats for an IP and UA, and increments their hit counts in memory.
func (c *MetricsCache) GetOrIncrementMetrics(ip, ua string, accessTime time.Time) *RequestMetrics {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Get or create IP stats
	ipStats, exists := c.ipStats[ip]
	if !exists {
		ipStats = &IPStats{
			TotalHits: 1,
			FirstSeen: accessTime,
			LastSeen:  accessTime,
		}
		c.ipStats[ip] = ipStats
	} else {
		// Increment hit count and update last seen
		ipStats.TotalHits++
		ipStats.LastSeen = accessTime
	}

	// Get or create UA stats
	ua = c.normalizeUA(ua)
	uaStats, exists := c.uaStats[ua]
	if !exists {
		// UA cap reached, so evict the least recently seen UA to make room.
		if c.config.MaxUniqueUserAgents > 0 && len(c.uaStats) >= c.config.MaxUniqueUserAgents {
			var oldest string
			var oldestSeen time.Time
			first := true
			for k, v := range c.uaStats {
				if first || v.LastSeen.Before(oldestSeen) {
					oldest = k
					oldestSeen = v.LastSeen
					first = false
				}
			}
			if oldest != "" {
				delete(c.uaStats, oldest)
			}
		}
		uaStats = &UAStats{
			TotalHits: 1,
			FirstSeen: accessTime,
			LastSeen:  accessTime,
		}
		c.uaStats[ua] = uaStats
	} else {
		// Increment hit count and update last seen
		uaStats.TotalHits++
		uaStats.LastSeen = accessTime
	}

	// Return metrics
	return &RequestMetrics{
		IPAddress:        ip,
		UserAgent:        ua,
		IPTotalHits:      ipStats.TotalHits,
		UATotalHits:      uaStats.TotalHits,
		TimeSinceIPFirst: accessTime.Sub(ipStats.FirstSeen),
		TimeSinceUAFirst: accessTime.Sub(uaStats.FirstSeen),
	}
}

// loadFromDB loads existing stats from the database into memory.
func (c *MetricsCache) loadFromDB() error {
	// Load IP stats
	rows, err := c.db.Query("SELECT ip_address, total_hits, first_seen, last_seen FROM stats_ip")
	if err != nil {
		return fmt.Errorf("failed to query IP stats: %w", err)
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	for rows.Next() {
		var ip string
		var hits int
		var firstSeen, lastSeen time.Time
		if err = rows.Scan(&ip, &hits, &firstSeen, &lastSeen); err != nil {
			return fmt.Errorf("failed to scan IP stats: %w", err)
		}
		c.ipStats[ip] = &IPStats{
			TotalHits: hits,
			FirstSeen: firstSeen,
			LastSeen:  lastSeen,
		}
	}

	// Load User Agent stats
	rows, err = c.db.Query("SELECT user_agent, total_hits, first_seen, last_seen FROM stats_user_agent")
	if err != nil {
		return fmt.Errorf("failed to query User Agent stats: %w", err)
	}
	defer func(rows *sql.Rows) {
		_ = rows.Close()
	}(rows)

	for rows.Next() {
		var ua string
		var hits int
		var firstSeen, lastSeen time.Time
		if err = rows.Scan(&ua, &hits, &firstSeen, &lastSeen); err != nil {
			return fmt.Errorf("failed to scan User Agent stats: %w", err)
		}
		c.uaStats[ua] = &UAStats{
			TotalHits: hits,
			FirstSeen: firstSeen,
			LastSeen:  lastSeen,
		}
	}

	return nil
}

// syncToDBIfDue checks if enough time has passed since the last sync and syncs if needed
func (c *MetricsCache) syncToDBIfDue() {
	// Use the syncMutex to ensure only one sync happens at a time
	c.syncMutex.Lock()
	defer c.syncMutex.Unlock()

	// Check if sync is needed (enough time has passed since last sync)
	timeSinceLastSync := time.Since(c.lastSyncTime)
	syncInterval := time.Duration(c.config.SyncIntervalSec) * time.Second

	if timeSinceLastSync >= syncInterval && !c.syncInProgress {
		c.syncDB()
	}
}

// syncDB performs the actual database sync
func (c *MetricsCache) syncDB() {
	c.syncInProgress = true
	defer func() {
		c.syncInProgress = false
	}()

	// Update the last sync time to the current time to prevent other goroutines from starting a sync
	c.lastSyncTime = time.Now()

	c.mu.RLock()
	// Create copies to minimize lock time
	ipCopy := make(map[string]*IPStats)
	uaCopy := make(map[string]*UAStats)

	for k, v := range c.ipStats {
		ipCopy[k] = &IPStats{
			TotalHits: v.TotalHits,
			FirstSeen: v.FirstSeen,
			LastSeen:  v.LastSeen,
		}
	}
	for k, v := range c.uaStats {
		uaCopy[k] = &UAStats{
			TotalHits: v.TotalHits,
			FirstSeen: v.FirstSeen,
			LastSeen:  v.LastSeen,
		}
	}
	c.mu.RUnlock()

	// Perform database operations without holding the cache lock
	tx, err := c.db.Begin()
	if err != nil {
		c.logger.Error("Failed to begin sync transaction", "error", err)
		// If sync fails, reset lastSyncTime to allow another attempt on the next tarpit hit
		c.lastSyncTime = time.Now().Add(-time.Duration(c.config.SyncIntervalSec+1) * time.Second)
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// Batch upsert IP stats
	for ip, stats := range ipCopy {
		_, err = tx.Exec(`
			INSERT INTO stats_ip (ip_address, total_hits, first_seen, last_seen) VALUES (?, ?, ?, ?)
			ON CONFLICT(ip_address) DO UPDATE SET total_hits = ?, last_seen = ?
		`, ip, stats.TotalHits, stats.FirstSeen, stats.LastSeen, stats.TotalHits, stats.LastSeen)
		if err != nil {
			c.logger.Error("Failed to sync IP stats to DB", "ip", ip, "error", err)
		}
	}

	// Batch upsert User Agent stats
	for ua, stats := range uaCopy {
		_, err = tx.Exec(`
			INSERT INTO stats_user_agent (user_agent, total_hits, first_seen, last_seen) VALUES (?, ?, ?, ?)
			ON CONFLICT(user_agent) DO UPDATE SET total_hits = ?, last_seen = ?
		`, ua, stats.TotalHits, stats.FirstSeen, stats.LastSeen, stats.TotalHits, stats.LastSeen)
		if err != nil {
			c.logger.Error("Failed to sync User Agent stats to DB", "user_agent", ua, "error", err)
		}
	}

	// Keep the user agent table at the configured cardinality cap (LRU by last_seen).
	if c.config.MaxUniqueUserAgents > 0 {
		_, err = tx.Exec(`
			DELETE FROM stats_user_agent
			WHERE rowid NOT IN (SELECT rowid FROM stats_user_agent ORDER BY last_seen DESC LIMIT ?)
		`, c.config.MaxUniqueUserAgents)
		if err != nil {
			c.logger.Error("Failed to prune user agent stats", "error", err)
		}
	}

	if err = tx.Commit(); err != nil {
		c.logger.Error("Failed to commit sync transaction", "error", err)
		// If sync fails, reset lastSyncTime to allow another attempt soon
		c.lastSyncTime = time.Now().Add(-time.Duration(c.config.SyncIntervalSec+1) * time.Second)
		return
	}

	c.logger.Debug("Stats sync completed", "entries_synced", len(ipCopy)+len(uaCopy))

	// Also run cleanup after successful sync
	c.cleanupOldEntries()
}

// cleanupOldEntries removes entries that meet the forget criteria from both memory and DB.
func (c *MetricsCache) cleanupOldEntries() {

	// If the threshold is 0 or less, cleanup is disabled.
	if c.config.ForgetThreshold <= 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	maxAge := time.Duration(c.config.ForgetDelayHours) * time.Hour

	// Check IPs for cleanup
	for ip, stats := range c.ipStats {
		if stats.TotalHits < c.config.ForgetThreshold && now.Sub(stats.LastSeen) > maxAge {
			// Remove from memory
			delete(c.ipStats, ip)
			// Also remove from database
			if _, err := c.db.Exec("DELETE FROM stats_ip WHERE ip_address = ?", ip); err != nil {
				c.logger.Error("Failed to delete old IP entry from DB", "ip", ip, "error", err)
			}
		}
	}

	// Check User Agents for cleanup
	for ua, stats := range c.uaStats {
		if stats.TotalHits < c.config.ForgetThreshold && now.Sub(stats.LastSeen) > maxAge {
			// Remove from memory
			delete(c.uaStats, ua)
			// Also remove from database
			if _, err := c.db.Exec("DELETE FROM stats_user_agent WHERE user_agent = ?", ua); err != nil {
				c.logger.Error("Failed to delete old User Agent entry from DB", "user_agent", ua, "error", err)
			}
		}
	}
}

func (s *StatsAPI) handleSummary(w http.ResponseWriter, r *http.Request) {
	if !hasScope(r, "stats:read") {
		respondWithError(w, http.StatusForbidden, "Forbidden")
		return
	}

	// Use the cache if available, otherwise fall back to database
	if s.cache != nil {
		s.cache.mu.RLock()
		totalRequests := 0
		for _, stats := range s.cache.ipStats {
			totalRequests += stats.TotalHits
		}
		uniqueIPs := len(s.cache.ipStats)
		uniqueUserAgents := len(s.cache.uaStats)
		s.cache.mu.RUnlock()

		summary := GlobalStatsSummary{
			TotalRequests:    int64(totalRequests),
			UniqueIPs:        int64(uniqueIPs),
			UniqueUserAgents: int64(uniqueUserAgents),
		}
		respondWithJSON(w, http.StatusOK, summary)
	} else {
		// Fallback to database query if cache is not available
		var summary GlobalStatsSummary
		_ = s.db.QueryRowContext(r.Context(), "SELECT COALESCE(SUM(total_hits), 0) FROM stats_ip").Scan(&summary.TotalRequests)
		_ = s.db.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM stats_ip").Scan(&summary.UniqueIPs)
		_ = s.db.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM stats_user_agent").Scan(&summary.UniqueUserAgents)
		respondWithJSON(w, http.StatusOK, summary)
	}
}

func (s *StatsAPI) handleTopIPs(w http.ResponseWriter, r *http.Request) {
	if !hasScope(r, "stats:read") {
		respondWithError(w, http.StatusForbidden, "Forbidden")
		return
	}

	// Use the cache if available, otherwise fall back to database
	if s.cache != nil {
		s.cache.mu.RLock()

		// Convert map to slice and sort by hits
		var results []map[string]any
		for ip, stats := range s.cache.ipStats {
			results = append(results, map[string]any{
				"ip_address": ip,
				"total_hits": stats.TotalHits,
				"first_seen": stats.FirstSeen,
				"last_seen":  stats.LastSeen,
			})
		}
		s.cache.mu.RUnlock()

		// Sort by hits descending
		sort.Slice(results, func(i, j int) bool {
			return results[i]["total_hits"].(int) > results[j]["total_hits"].(int)
		})

		// Limit to 100 results
		if len(results) > 100 {
			results = results[:100]
		}

		respondWithJSON(w, http.StatusOK, results)
	} else {
		// Fallback to database query
		rows, err := s.db.QueryContext(r.Context(), "SELECT ip_address, total_hits, first_seen, last_seen FROM stats_ip ORDER BY total_hits DESC LIMIT 100")
		if err != nil {
			s.logger.Error("Failed to query top IPs", "error", err)
			respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Database error: %v", err))
			return
		}
		defer func(rows *sql.Rows) {
			_ = rows.Close()
		}(rows)

		var results []map[string]any
		for rows.Next() {
			var ip string
			var hits int
			var first, last time.Time
			err = rows.Scan(&ip, &hits, &first, &last)
			if err != nil {
				s.logger.Error("Failed to scan top IPs", "error", err)
			}
			results = append(results, map[string]any{
				"ip_address": ip,
				"total_hits": hits,
				"first_seen": first,
				"last_seen":  last,
			})
		}
		respondWithJSON(w, http.StatusOK, results)
	}
}

func (s *StatsAPI) handleTopUserAgents(w http.ResponseWriter, r *http.Request) {
	if !hasScope(r, "stats:read") {
		respondWithError(w, http.StatusForbidden, "Forbidden")
		return
	}

	// Use the cache if available, otherwise fall back to database
	if s.cache != nil {
		s.cache.mu.RLock()

		// Convert map to slice and sort by hits
		var results []map[string]any
		for ua, stats := range s.cache.uaStats {
			results = append(results, map[string]any{
				"user_agent": ua,
				"total_hits": stats.TotalHits,
				"first_seen": stats.FirstSeen,
				"last_seen":  stats.LastSeen,
			})
		}
		s.cache.mu.RUnlock()

		// Sort by hits descending
		sort.Slice(results, func(i, j int) bool {
			return results[i]["total_hits"].(int) > results[j]["total_hits"].(int)
		})

		// Limit to 100 results
		if len(results) > 100 {
			results = results[:100]
		}

		respondWithJSON(w, http.StatusOK, results)
	} else {
		// Fallback to database query
		rows, err := s.db.QueryContext(r.Context(), "SELECT user_agent, total_hits, first_seen, last_seen FROM stats_user_agent ORDER BY total_hits DESC LIMIT 100")
		if err != nil {
			s.logger.Error("Failed to query top UAs", "error", err)
			respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Database error: %v", err))
			return
		}
		defer func(rows *sql.Rows) {
			_ = rows.Close()
		}(rows)

		var results []map[string]any
		for rows.Next() {
			var ua string
			var hits int
			var first, last time.Time
			err = rows.Scan(&ua, &hits, &first, &last)
			if err != nil {
				s.logger.Error("Failed to scan top UAs", "error", err)
			}
			results = append(results, map[string]any{
				"user_agent": ua,
				"total_hits": hits,
				"first_seen": first,
				"last_seen":  last,
			})
		}
		respondWithJSON(w, http.StatusOK, results)
	}
}

// handleResetAll clears all statistics from the database and cache.
func (s *StatsAPI) handleResetAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", "DELETE")
		respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !hasScope(r, "server:control") {
		respondWithError(w, http.StatusForbidden, "Forbidden: requires 'server:control' scope")
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		s.logger.Error("Failed to begin transaction for stats reset", "error", err)
		respondWithError(w, http.StatusInternalServerError, "Could not start database transaction")
		return
	}
	defer func(tx *sql.Tx) {
		_ = tx.Rollback()
	}(tx)

	if _, err = tx.ExecContext(r.Context(), "DELETE FROM stats_ip"); err != nil {
		s.logger.Error("Failed to delete from stats_ip", "error", err)
		respondWithError(w, http.StatusInternalServerError, "Failed to reset IP statistics")
		return
	}
	if _, err = tx.ExecContext(r.Context(), "DELETE FROM stats_user_agent"); err != nil {
		s.logger.Error("Failed to delete from stats_user_agent", "error", err)
		respondWithError(w, http.StatusInternalServerError, "Failed to reset User Agent statistics")
		return
	}

	if err = tx.Commit(); err != nil {
		s.logger.Error("Failed to commit transaction for stats reset", "error", err)
		respondWithError(w, http.StatusInternalServerError, "Failed to commit changes to database")
		return
	}

	// Clear the in-memory cache as well
	if s.cache != nil {
		s.cache.mu.Lock()
		s.cache.ipStats = make(map[string]*IPStats)
		s.cache.uaStats = make(map[string]*UAStats)
		s.cache.mu.Unlock()
	}

	s.logger.Warn("All statistics have been reset via API.")
	w.WriteHeader(http.StatusNoContent)
}

// normalizeUA truncates a user agent string to the configured max length in bytes.
func (c *MetricsCache) normalizeUA(ua string) string {
	if c.config.MaxUserAgentBytes > 0 && len(ua) > c.config.MaxUserAgentBytes {
		return ua[:c.config.MaxUserAgentBytes]
	}
	return ua
}
