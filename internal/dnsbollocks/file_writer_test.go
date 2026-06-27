package dnsbollocks

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestSafeFileWriter(t *testing.T) {
	// Setup
	dir := t.TempDir()
	targetFile := filepath.Join(dir, "config.json")

	// Discard logs during tests to keep console clean, or use Stderr to debug
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	var liveLogger atomic.Pointer[slog.Logger]
	liveLogger.Store(logger)

	// Initialize with extraSafety ON, passing the pointer to the atomic.Pointer
	fw := newSafeFileWriter(true, &liveLogger)

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
