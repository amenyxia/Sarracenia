package main

import (
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestMetricsCache opens a fresh stats DB and builds a MetricsCache with the given config.
func newTestMetricsCache(t *testing.T, cfg *StatsConfig) (*sql.DB, *MetricsCache) {
	t.Helper()
	db, err := initDB(filepath.Join(t.TempDir(), "stats.db"))
	if err != nil {
		t.Fatalf("initDB failed: %v", err)
	}
	if err := setupStatsSchema(db); err != nil {
		t.Fatalf("setupStatsSchema failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cache := &MetricsCache{
		ipStats:      make(map[string]*IPStats),
		uaStats:      make(map[string]*UAStats),
		db:           db,
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		config:       cfg,
		lastSyncTime: time.Now(),
	}
	return db, cache
}

// TestUALengthCap verifies that long user agents are truncated to the configured byte cap.
func TestUALengthCap(t *testing.T) {
	cfg := &StatsConfig{MaxUserAgentBytes: 16, MaxUniqueUserAgents: 1000}
	_, cache := newTestMetricsCache(t, cfg)

	now := time.Now()
	longUA := strings.Repeat("a", 32) // 32 bytes, exceeds the 16-byte cap

	metrics := cache.GetOrIncrementMetrics("1.2.3.4", longUA, now)

	if _, ok := cache.uaStats[longUA[:16]]; !ok {
		t.Errorf("truncated UA %q missing from cache", longUA[:16])
	}
	if len(cache.uaStats) != 1 {
		t.Errorf("uaStats count = %d, want 1", len(cache.uaStats))
	}
	if metrics.UATotalHits != 1 {
		t.Errorf("UATotalHits = %d, want 1", metrics.UATotalHits)
	}
}

// TestUACardinalityCap verifies LRU eviction when the unique UA cap is reached.
func TestUACardinalityCap(t *testing.T) {
	cfg := &StatsConfig{MaxUniqueUserAgents: 2, MaxUserAgentBytes: 512}
	_, cache := newTestMetricsCache(t, cfg)

	now := time.Now()
	cache.GetOrIncrementMetrics("1.1.1.1", "ua-one", now)
	cache.GetOrIncrementMetrics("1.1.1.1", "ua-two", now.Add(time.Second))
	metrics := cache.GetOrIncrementMetrics("1.1.1.1", "ua-three", now.Add(2*time.Second))

	if _, ok := cache.uaStats["ua-one"]; ok {
		t.Error("ua-one should have been evicted when the cap was reached")
	}
	if _, ok := cache.uaStats["ua-two"]; !ok {
		t.Error("ua-two missing from cache")
	}
	if _, ok := cache.uaStats["ua-three"]; !ok {
		t.Error("ua-three missing from cache")
	}
	if len(cache.uaStats) != 2 {
		t.Errorf("uaStats count = %d, want 2", len(cache.uaStats))
	}
	if metrics.UATotalHits != 1 {
		t.Errorf("UATotalHits = %d, want 1 (new UAs must still be tracked)", metrics.UATotalHits)
	}
}

// TestSyncPrunesToCap verifies the SQL LRU trim keeps only the N most recently seen UAs in the DB.
func TestSyncPrunesToCap(t *testing.T) {
	cfg := &StatsConfig{MaxUniqueUserAgents: 2, MaxUserAgentBytes: 512}
	db, cache := newTestMetricsCache(t, cfg)

	base := time.Now().Add(-time.Hour)
	rows := []struct {
		ua       string
		lastSeen time.Time
	}{
		{"ua-oldest", base},
		{"0123456789abcdef-1", base.Add(time.Minute)},
		{"0123456789abcdef-2", base.Add(2 * time.Minute)},
		{"ua-newer", base.Add(3 * time.Minute)},
		{"ua-newest", base.Add(4 * time.Minute)},
	}
	for _, row := range rows {
		if _, err := db.Exec(
			`INSERT INTO stats_user_agent (user_agent, total_hits, first_seen, last_seen) VALUES (?, 1, ?, ?)`,
			row.ua, row.lastSeen, row.lastSeen); err != nil {
			t.Fatalf("seed row failed: %v", err)
		}
	}

	cache.syncDB()

	var names []string
	rows2, err := db.Query("SELECT user_agent FROM stats_user_agent ORDER BY last_seen")
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	defer func() { _ = rows2.Close() }()
	for rows2.Next() {
		var name string
		if err := rows2.Scan(&name); err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		names = append(names, name)
	}
	if len(names) != 2 {
		t.Fatalf("rows remaining = %d, want 2 (the two most recently seen)", len(names))
	}
	want := []string{"ua-newer", "ua-newest"}
	for i, name := range names {
		if name != want[i] {
			t.Errorf("row %d = %q, want %q", i+1, name, want[i])
		}
	}
}
