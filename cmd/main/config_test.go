package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DeRuina/timberjack"
)

func TestLogRotationKeepsBackups(t *testing.T) {
	dir := t.TempDir()
	lc := &LogsConfig{
		Filename:           filepath.Join(dir, "app.log"),
		MaxSize:            1,
		MaxBackups:         2,
		Compression:        "none",
		BackupTimeFormat:   "2006-01-02-15-04-05.000", // millisecond precision so rapid rotations get distinct names
		AppendTimeAfterExt: true,
		FileMode:           os.FileMode(0644),
	}
	l, ok := lc.getLogger().(*timberjack.Logger)
	if !ok {
		t.Fatal("getLogger() did not return a *timberjack.Logger")
	}
	defer func(l *timberjack.Logger) {
		err := l.Close()
		if err != nil {
			t.Errorf("failed to close logger: %v", err)
		}
	}(l)

	for i := range 4 {
		if _, err := l.Write([]byte(strings.Repeat("x", 1024) + "\n")); err != nil {
			t.Fatalf("write %d failed: %v", i, err)
		}
		if err := l.RotateWithReason("test"); err != nil {
			t.Fatalf("rotate %d failed: %v", i, err)
		}
		time.Sleep(20 * time.Millisecond) // keep backup timestamps distinct
	}

	// Backup cleanup is asynchronous, so poll for the final state:
	// active log + 2 backups.
	deadline := time.Now().Add(2 * time.Second)
	for {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read dir failed: %v", err)
		}
		if len(entries) == 3 {
			break
		}
		if time.Now().After(deadline) {
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.Name())
			}
			t.Fatalf("dir entries = %v, want active log + 2 backups", names)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
