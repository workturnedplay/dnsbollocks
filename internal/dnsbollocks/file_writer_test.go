//go:build windows
// +build windows

package dnsbollocks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestSafeFileWriter(t *testing.T) {
	// Setup
	dir := t.TempDir()
	targetFile := filepath.Join(dir, "config.json")

	// Discard logs during tests to keep console clean, or use Stderr to debug
	logger := slog.New(slog.NewTextHandler(
		//os.Stderr,
		io.Discard,
		&slog.HandlerOptions{Level: slog.LevelError}))

	var liveLogger atomic.Pointer[slog.Logger]
	liveLogger.Store(logger)

	// Initialize with extraSafety ON, passing the pointer to the atomic.Pointer
	fw := newWin11SafeFileWriter(true, &liveLogger)

	// --- Test 1: Normal Write ---
	data := []byte(`{"status": "ok"}`)
	err := fw.SafeWriteFile(targetFile, data, 0644)
	if err != nil {
		t.Fatalf("SafeWriteFile failed: %v", err)
	}

	// Verify file content
	readData, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatalf("Failed to read created file: %v", err)
	}
	if !bytes.Equal(readData, data) {
		t.Errorf("Expected file content %q, got %q", data, readData)
	}

	// Verify the power loss file was cleaned up
	powerLossFile := targetFile + powerlossFileExtension
	if _, err2 := os.Stat(powerLossFile); !os.IsNotExist(err2) {
		t.Error("Expected power loss staging file to be deleted after successful write")
	}

	// --- Test 2: CheckPowerLossFile (Clean State) ---
	// This should NOT panic because the file doesn't exist
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("CheckPowerLossFile panicked unexpectedly on a clean state: %v", r)
		}
	}()
	fw.CheckPowerLossFile(targetFile)

	// --- Test 3: CheckPowerLossFile (Simulated Power Loss) ---
	// Manually create a non-empty power loss staging file
	err = os.WriteFile(powerLossFile, []byte("interrupted partial write data"), 0644)
	if err != nil {
		t.Fatalf("Failed to mock power loss file: %v", err)
	}

	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		fw.CheckPowerLossFile(targetFile)
	}()

	if !panicked {
		t.Error("Expected CheckPowerLossFile to panic when a non-empty power loss file exists")
	}

	// --- Test 4: CheckPowerLossFile (Empty Staging File) ---
	// Truncate to 0 bytes - it should log a warning but NOT panic
	os.WriteFile(powerLossFile, []byte(""), 0644)

	emptyPanicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				emptyPanicked = true
			}
		}()
		fw.CheckPowerLossFile(targetFile)
	}()

	if emptyPanicked {
		t.Error("Expected CheckPowerLossFile to NOT panic when power loss file is exactly 0 bytes")
	}

	// --- Test 5: ExtraSafety OFF ---
	fw.SetExtraSafety(false)
	newData := []byte(`{"status": "updated"}`)
	err = fw.SafeWriteFile(targetFile, newData, 0644)
	if err != nil {
		t.Fatalf("SafeWriteFile failed with ExtraSafety off: %v", err)
	}
}

func TestSafeFileWriter_SequentialWrites(t *testing.T) {
	dir := t.TempDir()
	targetFile := filepath.Join(dir, "config.json")

	logger := slog.New(slog.NewTextHandler(
		//os.Stderr,
		io.Discard,
		&slog.HandlerOptions{Level: slog.LevelError}))
	var liveLogger atomic.Pointer[slog.Logger]
	liveLogger.Store(logger)
	fw := newWin11SafeFileWriter(true, &liveLogger)

	stagingFile := targetFile + powerlossFileExtension

	for i := range 5 {
		data := []byte(fmt.Sprintf(`{"iteration": %d}`, i))
		if err := fw.SafeWriteFile(targetFile, data, 0644); err != nil {
			t.Fatalf("write %d failed: %v", i, err)
		}

		// Staging must be gone after every write, not just the first.
		if _, err := os.Stat(stagingFile); !os.IsNotExist(err) {
			t.Errorf("write %d: staging file still exists after successful write", i)
		}

		got, err := os.ReadFile(targetFile)
		if err != nil {
			t.Fatalf("write %d: cannot read target file: %v", i, err)
		}
		if !bytes.Equal(got, data) {
			t.Errorf("write %d: content mismatch: got %q, want %q", i, got, data)
		}
	}
}

func TestSafeFileWriter_ConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	targetFile := filepath.Join(dir, "config.json")

	var liveLogger atomic.Pointer[slog.Logger]
	liveLogger.Store(slog.New(slog.NewTextHandler(io.Discard, nil)))
	fw := newWin11SafeFileWriter(true, &liveLogger)

	const goroutines = 10
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			data := []byte(fmt.Sprintf(`{"writer": %d}`, n))
			if err := fw.SafeWriteFile(targetFile, data, 0644); err != nil {
				errCh <- fmt.Errorf("goroutine %d: %w", n, err)
			}
		}(i)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent write error: %v", err)
	}

	// File must exist and contain valid JSON — one of the writers won cleanly.
	got, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatalf("final file unreadable: %v", err)
	}
	if !json.Valid(got) {
		t.Errorf("final file is not valid JSON after concurrent writes: %q", got)
	}

	// No staging file left behind regardless of which writer won.
	if _, err := os.Stat(targetFile + powerlossFileExtension); !os.IsNotExist(err) {
		t.Error("staging file left behind after concurrent writes")
	}
}

func TestSafeFileWriter_ExtraSafetyOff_NoStagingFileCreated(t *testing.T) {
	dir := t.TempDir()
	targetFile := filepath.Join(dir, "config.json")

	var liveLogger atomic.Pointer[slog.Logger]
	liveLogger.Store(slog.New(slog.NewTextHandler(io.Discard, nil)))
	fw := newWin11SafeFileWriter(false, &liveLogger)

	if err := fw.SafeWriteFile(targetFile, []byte(`{"ok":true}`), 0644); err != nil {
		t.Fatalf("SafeWriteFile failed: %v", err)
	}

	// When ExtraSafety is OFF the staging file must never appear at all.
	if _, err := os.Stat(targetFile + powerlossFileExtension); !os.IsNotExist(err) {
		t.Error("staging file was created despite ExtraSafety being OFF")
	}
}

func TestSafeFileWriter_SetExtraSafety_Toggle(t *testing.T) {
	dir := t.TempDir()
	targetFile := filepath.Join(dir, "config.json")

	var liveLogger atomic.Pointer[slog.Logger]
	liveLogger.Store(slog.New(slog.NewTextHandler(io.Discard, nil)))
	fw := newWin11SafeFileWriter(false, &liveLogger)

	// --- OFF → write → no staging ---
	if err := fw.SafeWriteFile(targetFile, []byte(`{"v":1}`), 0644); err != nil {
		t.Fatalf("write with ExtraSafety OFF failed: %v", err)
	}
	if _, err := os.Stat(targetFile + powerlossFileExtension); !os.IsNotExist(err) {
		t.Error("staging file must not exist when ExtraSafety is OFF")
	}

	// --- toggle ON → write → staging cleaned up ---
	fw.SetExtraSafety(true)
	data2 := []byte(`{"v":2}`)
	if err := fw.SafeWriteFile(targetFile, data2, 0644); err != nil {
		t.Fatalf("write with ExtraSafety ON failed: %v", err)
	}
	if _, err := os.Stat(targetFile + powerlossFileExtension); !os.IsNotExist(err) {
		t.Error("staging file must be cleaned up after successful write with ExtraSafety ON")
	}
	got, _ := os.ReadFile(targetFile)
	if !bytes.Equal(got, data2) {
		t.Errorf("content mismatch after toggle: got %q, want %q", got, data2)
	}

	// --- toggle OFF again → staging must not reappear ---
	fw.SetExtraSafety(false)
	data3 := []byte(`{"v":3}`)
	if err := fw.SafeWriteFile(targetFile, data3, 0644); err != nil {
		t.Fatalf("write after second toggle failed: %v", err)
	}
	if _, err := os.Stat(targetFile + powerlossFileExtension); !os.IsNotExist(err) {
		t.Error("staging file must not exist after toggling ExtraSafety back OFF")
	}
}

func TestSafeFileWriter_CheckPowerLossFile_EmptyFilename(t *testing.T) {
	var liveLogger atomic.Pointer[slog.Logger]
	liveLogger.Store(slog.New(slog.NewTextHandler(io.Discard, nil)))
	fw := newWin11SafeFileWriter(true, &liveLogger)

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("CheckPowerLossFile(\"\") panicked unexpectedly: %v", r)
		}
	}()
	fw.CheckPowerLossFile("")
}
