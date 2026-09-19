//go:build windows
// +build windows

package dnsbollocks

import (
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type countingSyncer struct {
	n   atomic.Int64
	err error
}

func (c *countingSyncer) Sync() error {
	c.n.Add(1)
	return c.err
}

func waitForSyncCount(s *countingSyncer, atLeast int64, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.n.Load() >= atLeast {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return s.n.Load() >= atLeast
}

func TestLogSyncCoordinator_MessageCountTrigger(t *testing.T) {
	s := &countingSyncer{}
	c := newLogSyncCoordinator(0, 3)
	c.register("a", s)
	c.Start()
	defer func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	c.NoteMessage()
	c.NoteMessage()
	time.Sleep(150 * time.Millisecond)
	if got := s.n.Load(); got != 0 {
		t.Fatalf("expected no sync after 2 of 3 messages, got %d", got)
	}
	c.NoteMessage()
	if !waitForSyncCount(s, 1, 2*time.Second) {
		t.Fatal("expected a sync after 3 messages")
	}

	// Counter was reset: two more messages must not sync again.
	c.NoteMessage()
	c.NoteMessage()
	time.Sleep(150 * time.Millisecond)
	if got := s.n.Load(); got != 1 {
		t.Fatalf("expected counter reset after sync (still 1 sync), got %d", got)
	}
}

func TestLogSyncCoordinator_IntervalTrigger_ContinuesAfterSyncError(t *testing.T) {
	s := &countingSyncer{err: errors.New("simulated sync failure")}
	c := newLogSyncCoordinator(1, 0)
	c.register("a", s)
	c.Start()
	defer func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()
	if !waitForSyncCount(s, 2, 4*time.Second) {
		t.Fatalf("expected repeated interval syncs despite errors, got %d", s.n.Load())
	}
}

func TestLogSyncCoordinator_DisabledIsInertAndCloseIsIdempotent(t *testing.T) {
	s := &countingSyncer{}
	c := newLogSyncCoordinator(0, 0)
	c.register("a", s)
	c.Start()
	c.NoteMessage()
	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if s.n.Load() != 0 {
		t.Fatal("disabled coordinator must never sync")
	}
	var nilCoord *logSyncCoordinator
	nilCoord.NoteMessage() // must not panic
}

func TestRotatingLogWriter_SyncAndOnWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sync.log")
	w, err := newRotatingLogWriter(path, 100, discardLogger())
	if err != nil {
		t.Fatalf("newRotatingLogWriter: %v", err)
	}
	var writes atomic.Int64
	w.onWrite = func() { writes.Add(1) }

	if _, err := w.Write([]byte("hello\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if writes.Load() != 1 {
		t.Errorf("expected onWrite called once, got %d", writes.Load())
	}
	if err := w.Sync(); err != nil {
		t.Errorf("Sync: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := w.Sync(); err != nil {
		t.Errorf("Sync after Close should be a no-op, got: %v", err)
	}
}

func TestSanitizeAndValidateConfig_LogSyncSettings(t *testing.T) {
	t.Parallel()
	def := defaultConfig()

	t.Run("zero is valid (disables trigger)", func(t *testing.T) {
		t.Parallel()
		cfg := defaultConfig()
		cfg.LogSyncIntervalSec = 0
		cfg.LogSyncEveryNMessages = 0
		resolved, raw, modified, err := sanitizeHelper(t, cfg, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resolved.LogSyncIntervalSec != 0 || raw.LogSyncIntervalSec != 0 ||
			resolved.LogSyncEveryNMessages != 0 || raw.LogSyncEveryNMessages != 0 {
			t.Error("zero must be preserved")
		}
		if modified {
			t.Error("expected modified=false for zero values")
		}
	})

	t.Run("negative clamped to default", func(t *testing.T) {
		t.Parallel()
		cfg := defaultConfig()
		cfg.LogSyncIntervalSec = -1
		cfg.LogSyncEveryNMessages = -5
		resolved, raw, modified, err := sanitizeHelper(t, cfg, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resolved.LogSyncIntervalSec != def.LogSyncIntervalSec || raw.LogSyncIntervalSec != def.LogSyncIntervalSec {
			t.Errorf("interval not clamped: resolved=%d raw=%d", resolved.LogSyncIntervalSec, raw.LogSyncIntervalSec)
		}
		if resolved.LogSyncEveryNMessages != def.LogSyncEveryNMessages || raw.LogSyncEveryNMessages != def.LogSyncEveryNMessages {
			t.Errorf("every-N not clamped: resolved=%d raw=%d", resolved.LogSyncEveryNMessages, raw.LogSyncEveryNMessages)
		}
		if !modified {
			t.Error("expected modified=true when clamping")
		}
	})
}