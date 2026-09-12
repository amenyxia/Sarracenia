package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/DeRuina/timberjack"
	"github.com/amenyxia/Sarracenia/pkg/templating"
	"github.com/natefinch/atomic"
)

// ServerConfig holds the configuration for the HTTP servers.
type ServerConfig struct {
	ServerAddr          string        `json:"server_addr"`
	ApiAddr             string        `json:"api_addr"`
	LogLevel            string        `json:"log_level"`
	TrustedProxies      []string      `json:"trusted_proxies"`
	DataDir             string        `json:"data_dir"`
	MarkovDatabasePath  string        `json:"markov_database_path"`
	AuthDatabasePath    string        `json:"auth_database_path"`
	StatsDatabasePath   string        `json:"stats_database_path"`
	DashboardTmplPath   string        `json:"dashboard_tmpl_path"`
	DashboardStaticPath string        `json:"dashboard_static_path"`
	EnabledTemplates    []string      `json:"enabled_templates"`
	TarpitConfig        *TarpitConfig `json:"tarpit_config"`
	StatsConfig         *StatsConfig  `json:"stats_config"`
	LogsConfig          *LogsConfig   `json:"logs_config"`
}

// TarpitConfig holds settings for response delaying and drip-feeding.
type TarpitConfig struct {
	EnableDripFeed    bool              `json:"enable_drip_feed"`
	InitialDelayMin   int               `json:"min_initial_delay_ms"`
	InitialDelayMax   int               `json:"max_initial_delay_ms"`
	DripFeedDelayMin  int               `json:"min_drip_feed_delay_ms"`
	DripFeedDelayMax  int               `json:"max_drip_feed_delay_ms"`
	DripFeedChunksMin int               `json:"min_drip_feed_chunks"`
	DripFeedChunksMax int               `json:"max_drip_feed_chunks"`
	Headers           map[string]string `json:"headers"`
}

// StatsConfig holds settings for statistics caching and cleanup.
type StatsConfig struct {
	SyncIntervalSec     int `json:"sync_interval_sec"`
	ForgetThreshold     int `json:"forget_threshold"`
	ForgetDelayHours    int `json:"forget_delay_hours"`
	MaxUserAgentBytes   int `json:"max_user_agent_bytes"`
	MaxUniqueUserAgents int `json:"max_unique_user_agents"`
}

// LogsConfig holds settings for log rotation.
type LogsConfig struct {
	Filename           string        `json:"filename"`
	MaxSize            int           `json:"max_size"`
	MaxAge             int           `json:"max_age"`
	MaxBackups         int           `json:"max_backups"`
	LocalTime          bool          `json:"local_time"`
	Compression        string        `json:"compression"`
	RotationInterval   time.Duration `json:"rotation_interval"`
	RotateAtMinutes    []int         `json:"rotate_at_minutes"`
	RotateAt           []string      `json:"rotate_at"`
	BackupTimeFormat   string        `json:"backup_time_format"`
	AppendTimeAfterExt bool          `json:"append_time_after_ext"`
	FileMode           os.FileMode   `json:"file_mode"`
}

// Config is the top-level configuration struct that aggregates all other configs.
type Config struct {
	Server    *ServerConfig              `json:"server_config"`
	Templates *templating.TemplateConfig `json:"template_config"`
	Threat    *ThreatConfig              `json:"threat_config"`
}

// DefaultServerConfig creates a server configuration with default values.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		ServerAddr:          ":7277",
		ApiAddr:             ":7278",
		LogLevel:            "info",
		TrustedProxies:      []string{},
		DataDir:             "./data",
		MarkovDatabasePath:  "./data/sarracenia_markov.db?_journal_mode=WAL&_busy_timeout=5000",
		AuthDatabasePath:    "./data/sarracenia_auth.db?_journal_mode=WAL&_busy_timeout=5000",
		StatsDatabasePath:   "./data/sarracenia_stats.db?_journal_mode=WAL&_busy_timeout=5000",
		DashboardTmplPath:   "./data/dashboard/templates/",
		DashboardStaticPath: "./data/dashboard/static/",
		EnabledTemplates:    []string{"page.tmpl.html"},
		TarpitConfig: &TarpitConfig{
			EnableDripFeed:    false,
			InitialDelayMin:   0,
			InitialDelayMax:   15000,
			DripFeedDelayMin:  500,
			DripFeedDelayMax:  1000,
			DripFeedChunksMin: 1,
			DripFeedChunksMax: 20,
			Headers: map[string]string{
				"Cache-Control":           "no-store, no-cache",
				"Pragma":                  "no-cache",
				"Expires":                 "0",
				"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';",
				"Content-Type":            "text/html; charset=utf-8",
			},
		},
		StatsConfig: &StatsConfig{
			SyncIntervalSec:     30,
			ForgetThreshold:     10,
			ForgetDelayHours:    24,
			MaxUserAgentBytes:   512,
			MaxUniqueUserAgents: 1000,
		},
		LogsConfig: &LogsConfig{
			Filename:           "./logs",
			MaxSize:            500,
			MaxBackups:         3,
			MaxAge:             28,
			Compression:        "gzip",
			LocalTime:          true,
			RotationInterval:   24,
			RotateAtMinutes:    []int{},
			RotateAt:           []string{},
			BackupTimeFormat:   "2006-01-02-15-04-05",
			AppendTimeAfterExt: true,
			FileMode:           os.FileMode(0644),
		},
	}
}

// LoadConfig reads the configuration from a JSON file at the given path.
// If the file doesn't exist, it creates one with default values.
func LoadConfig(path string) (*Config, error) {
	// Initialize with default configurations
	config := &Config{
		Server:    DefaultServerConfig(),
		Templates: templating.DefaultConfig(),
		Threat:    DefaultThreatConfig(),
	}

	file, err := os.ReadFile(path)
	if err != nil {
		// If the file doesn't exist, create it with the default config.
		if os.IsNotExist(err) {
			var data []byte
			data, err = json.MarshalIndent(config, "", "  ")
			if err != nil {
				return nil, fmt.Errorf("failed to marshal default config: %w", err)
			}
			if err = atomic.WriteFile(path, bytes.NewReader(data)); err != nil {
				// Log a warning instead of failing, as the server can still run with defaults.
				fmt.Printf("warning: failed to write default config file: %v\n", err)
			}
			return config, nil
		}
		// For other errors (e.g., permission denied), return the error.
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Unmarshal the JSON from the file into the config struct.
	if err = json.Unmarshal(file, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return config, nil
}

// ConfigManager handles thread-safe access to configuration and derived state (trusted proxies).
type ConfigManager struct {
	config       *Config
	mu           sync.RWMutex
	trustedCIDRs []*net.IPNet
	trustedIPs   []net.IP
	configPath   string
	logger       *slog.Logger
	tm           *templating.TemplateManager
}

// NewConfigManager loads the config and initializes the manager.
func NewConfigManager(path string) (*ConfigManager, error) {
	cfg, err := LoadConfig(path)
	if err != nil {
		return nil, err
	}

	cm := &ConfigManager{
		config:     cfg,
		configPath: path,
		// Log to stdout before the application-specific logger is set.
		logger: slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{})),
	}
	cm.refreshCache()

	return cm, nil
}

// SetTemplateManager registers the template manager to receive config updates.
func (cm *ConfigManager) SetTemplateManager(tm *templating.TemplateManager) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.tm = tm
	// Ensure TM starts with current config
	if tm != nil {
		tm.SetConfig(cm.config.Templates)
	}
}

// SetLogger sets the logger. That's about it.
func (cm *ConfigManager) SetLogger(logger *slog.Logger) {
	cm.logger = logger
}

// Get returns a thread-safe copy of the current configuration.
func (cm *ConfigManager) Get() Config {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	// Return a dereferenced copy to prevent external modification of the internal state
	return *cm.config
}

// Update updates the configuration, saves it to disk, and refreshes derived state.
func (cm *ConfigManager) Update(newConfig Config) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// If we have a TemplateManager, try to apply the new config to it first.
	if cm.tm != nil {
		// Keep reference to old template config
		oldTmplConfig := cm.config.Templates

		cm.tm.SetConfig(newConfig.Templates)
		if err := cm.tm.Refresh(); err != nil {
			// Rollback to old config
			cm.tm.SetConfig(oldTmplConfig)
			_ = cm.tm.Refresh()
			return fmt.Errorf("template configuration rejected: %w", err)
		}
	}

	*cm.config = newConfig
	cm.refreshCache()

	data, err := json.MarshalIndent(cm.config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := atomic.WriteFile(cm.configPath, bytes.NewReader(data)); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// IsTrusted checks if an IP is in the trusted proxies list using the cache.
func (cm *ConfigManager) IsTrusted(ipAddr string) bool {
	parsedIP := net.ParseIP(ipAddr)
	if parsedIP == nil {
		return false
	}

	cm.mu.RLock()
	defer cm.mu.RUnlock()

	for _, ipNet := range cm.trustedCIDRs {
		if ipNet.Contains(parsedIP) {
			return true
		}
	}

	for _, trustedIP := range cm.trustedIPs {
		if trustedIP.Equal(parsedIP) {
			return true
		}
	}

	return false
}

// refreshCache rebuilds the binary IP lists from the config strings.
func (cm *ConfigManager) refreshCache() {
	var cidrs []*net.IPNet
	var ips []net.IP

	for _, t := range cm.config.Server.TrustedProxies {
		if strings.Contains(t, "/") {
			_, ipNet, err := net.ParseCIDR(t)
			if err == nil {
				cidrs = append(cidrs, ipNet)
			} else {
				cm.logger.Warn("Failed to parse trusted proxy CIDR", "cidr", t, "error", err)
			}
		} else {
			ip := net.ParseIP(t)
			if ip != nil {
				ips = append(ips, ip)
			} else {
				cm.logger.Warn("Failed to parse trusted proxy IP", "ip", t)
			}
		}
	}
	cm.trustedCIDRs = cidrs
	cm.trustedIPs = ips
}

// getLogger returns a configured timberjack.Logger
func (lc *LogsConfig) getLogger() io.WriteCloser {
	return &timberjack.Logger{
		Filename:           lc.Filename,
		MaxSize:            lc.MaxSize,
		MaxAge:             lc.MaxAge,
		MaxBackups:         lc.MaxBackups,
		LocalTime:          lc.LocalTime,
		Compression:        lc.Compression,
		RotationInterval:   lc.RotationInterval * time.Hour,
		RotateAtMinutes:    lc.RotateAtMinutes,
		RotateAt:           lc.RotateAt,
		BackupTimeFormat:   lc.BackupTimeFormat,
		AppendTimeAfterExt: lc.AppendTimeAfterExt,
		FileMode:           lc.FileMode,
	}
}
