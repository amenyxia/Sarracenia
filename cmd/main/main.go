package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/amenyxia/Sarracenia/pkg/markov"
)

var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)

func main() {
	// The base logger is purely to log startup and startup errors,
	// as the logger rotation config cannot be loaded at this point.
	baseLogger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	actionChan := make(chan string, 1)

	go func() {
		osSignalChan := make(chan os.Signal, 1)
		signal.Notify(osSignalChan, syscall.SIGINT, syscall.SIGTERM)
		<-osSignalChan // Wait for a signal
		baseLogger.Info("OS signal received, initiating shutdown.")
		actionChan <- actionShutdown
	}()

	for {
		cleanupOldTempFiles(baseLogger)
		action, err := run(actionChan)
		if err != nil {
			baseLogger.Error("An error occurred during server run, shutting down.", "error", err)
			break
		}

		if action == actionRestart {
			baseLogger.Info("--- Server Restarting ---")
			continue
		} else {
			break
		}
	}

	baseLogger.Info("Sarracenia has shut down.")
}

// run is the main loop that hosts both servers, and returns whenever the server is shutdown or restarted
func run(actionChan chan string) (string, error) {

	cm, err := NewConfigManager("./config.json")
	if err != nil {
		return "", fmt.Errorf("failed to initialize config manager: %w", err)
	}

	activeConfig := cm.Get()
	var logLevel slog.Level
	switch strings.ToLower(activeConfig.Server.LogLevel) {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}
	logWriter := activeConfig.Server.LogsConfig.getLogger()
	logger := slog.New(slog.NewTextHandler(logWriter, &slog.HandlerOptions{Level: logLevel}))
	logger.Info("Starting server cycle...")
	cm.SetLogger(logger)

	markovDB, err := initDB(activeConfig.Server.MarkovDatabasePath)
	if err != nil {
		return "", fmt.Errorf("failed to initialize markov database: %w", err)
	}
	authDB, err := initDB(activeConfig.Server.AuthDatabasePath)
	if err != nil {
		return "", fmt.Errorf("failed to initialize auth database: %w", err)
	}
	statsDB, err := initDB(activeConfig.Server.StatsDatabasePath)
	if err != nil {
		return "", fmt.Errorf("failed to initialize stats database: %w", err)
	}

	if err = markov.SetupSchema(markovDB); err != nil {
		logger.Error("Failed to setup markov schema", "error", err)
	}
	if err = setupAuthSchema(authDB); err != nil {
		logger.Error("Failed to setup auth schema", "error", err)
	}
	if err = setupStatsSchema(statsDB); err != nil {
		logger.Error("Failed to setup stats schema", "error", err)
	}
	if err = setupWhitelistSchema(authDB); err != nil {
		logger.Error("Failed to setup whitelist schema", "error", err)
	}

	apiHttpServer := &http.Server{
		Addr:              activeConfig.Server.ApiAddr,
		ReadHeaderTimeout: 20 * time.Second,
		ReadTimeout:       15 * time.Minute,
		WriteTimeout:      1 * time.Minute,
		IdleTimeout:       60 * time.Second,
	}

	// Tarpit server must have a long WriteTimeout to accommodate delays and drip-feeding.
	tarpitHttpServer := &http.Server{
		Addr:         activeConfig.Server.ServerAddr,
		ReadTimeout:  5 * time.Second,  // Still protect against slow requests.
		WriteTimeout: 0,                // No timeout on writes so the tarpit can drip-feed for a long time.
		IdleTimeout:  60 * time.Second, // Clean up idle keep-alive connections.
	}

	server, err := NewServer(cm, logger, markovDB, authDB, statsDB, actionChan)
	if err != nil {
		_ = markovDB.Close()
		_ = authDB.Close()
		_ = statsDB.Close()
		return "", fmt.Errorf("failed to create server object: %w", err)
	}

	tarpitHttpServer.Handler = server.tarpitMux
	apiHttpServer.Handler = server.apiMux

	go func() {
		logger.Info("Starting api/dashboard server", "address", apiHttpServer.Addr)
		if err := apiHttpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Api server failed", "error", err)
		}
	}()

	go func() {
		logger.Info("Starting Sarracenia tarpit server", "address", tarpitHttpServer.Addr)
		if err := tarpitHttpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Tarpit server failed", "error", err)
		}
	}()

	action := <-actionChan // Block here until API or OS signal sends an action.

	logger.Info("Stopping servers for " + action + "...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err = apiHttpServer.Shutdown(ctx); err != nil {
		logger.Error("Api server shutdown failed", "error", err)
	}
	if err = tarpitHttpServer.Shutdown(ctx); err != nil {
		logger.Error("Tarpit server shutdown failed", "error", err)
	}
	logger.Info("HTTP servers stopped.")

	logger.Info("Closing database connections.")
	if err = markovDB.Close(); err != nil {
		logger.Error("Failed to close markov database", "error", err)
	}
	if err = authDB.Close(); err != nil {
		logger.Error("Failed to close auth database", "error", err)
	}
	if err = statsDB.Close(); err != nil {
		logger.Error("Failed to close stats database", "error", err)
	}
	logger.Info("Database connections closed.")

	logger.Info("Closing logger.")
	err = logWriter.Close()
	if err != nil {
		logger.Error("Failed to close log file", "error", err)
	}
	return action, nil
}

// cleanupOldTempFiles removes any orphaned temporary files from previous runs.
func cleanupOldTempFiles(logger *slog.Logger) {
	tempDir := filepath.Join("./data", "tmp")
	files, err := filepath.Glob(filepath.Join(tempDir, "*"))
	if err != nil {
		logger.Error("Failed to search for old temp files", "error", err)
		return
	}
	if len(files) > 0 {
		logger.Info("Cleaning up old temp files", "count", len(files))
		for _, f := range files {
			if err = os.Remove(f); err != nil {
				logger.Warn("Failed to remove old temp file", "file", f, "error", err)
			}
		}
	}
}
