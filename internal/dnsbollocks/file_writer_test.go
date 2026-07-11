//go:build windows
// +build windows

package dnsbollocks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/workturnedplay/wincoe"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// func discardLogger() *slog.Logger {
// 	return slog.New(slog.NewTextHandler(io.Discard, nil))
// }

// Helper to restore OS hooks after each mock test
func restoreHooks() {
	wincoe.OsStatFunc = os.Stat
	wincoe.OsRenameFunc = os.Rename
	wincoe.OsRemoveFunc = os.Remove
	wincoe.ReplaceFileFunc = wincoe.ReplaceFile
}

func TestWin11SafeFileWriter_Mock_ReplaceFileFails_CatastrophicPanic(t *testing.T) {
	defer restoreHooks()
	dir := t.TempDir()
	targetFile := filepath.Join(dir, "config.json")
	wrErr := os.WriteFile(targetFile, []byte("old"), 0600)
	if wrErr != nil {
		t.Errorf("WriteFile failed so tests will fail, err: %v", wrErr)
	}

	// MOCK 1: ReplaceFile fails
	wincoe.ReplaceFileFunc = func(replaced, replacement, backup string, flags uint32) error {
		return fmt.Errorf("mock ReplaceFileW failure")
	}

	// MOCK 2: Remove fails AND sabotages the file so Truncate fails too
	wincoe.OsRemoveFunc = func(name string) error {
		// THE FIX: Strip write permissions. When TruncateStagingFileToZero tries
		// to open this with O_WRONLY|O_TRUNC, Windows will throw an Access Denied error.
		chmodErr := os.Chmod(name, 0400)
		if chmodErr != nil {
			t.Errorf("Chmod failed so tests will fail, err: %v", chmodErr)
		}
		return fmt.Errorf("mock os.Remove failure")
	}

	var liveLogger atomic.Pointer[slog.Logger]
	liveLogger.Store(discardLogger())
	fw := wincoe.NewWin11SafeFileWriter(true, 1, 10, &liveLogger)

	// Catch the expected safety panic
	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		_ = fw.SafeWriteFile(targetFile, []byte("new"), 0644) //nolint:errcheck // on purpose
	}()

	// Reset permissions so t.TempDir() cleanup doesn't fail on a read-only file
	chmodErr := os.Chmod(targetFile+wincoe.PowerlossFileExtension, 0600)
	if chmodErr != nil {
		t.Errorf("Chmod failed so cleanup will fail, err: %v", chmodErr)
	}

	if !panicked {
		t.Error("Expected catastrophic panic when ReplaceFile, Remove, and Truncate ALL fail")
	}
}

func TestWin11SafeFileWriter_Mock_FirstBootRenameFails_CatastrophicPanic(t *testing.T) {
	defer restoreHooks()
	dir := t.TempDir()
	targetFile := filepath.Join(dir, "new_config.json")

	// Target does NOT exist -> triggers initial os.Rename path

	// MOCK 1: Rename fails AND sabotages the file
	wincoe.OsRenameFunc = func(oldpath, newpath string) error {
		// THE FIX: Make read-only here so the subsequent truncate attempt crashes.
		chmodErr := os.Chmod(oldpath, 0400)
		if chmodErr != nil {
			t.Errorf("Chmod failed so tests will fail, err: %v", chmodErr)
		}
		return fmt.Errorf("mock os.Rename failure")
	}
	// MOCK 2: Remove fails
	wincoe.OsRemoveFunc = func(name string) error {
		return fmt.Errorf("mock os.Remove failure")
	}

	var liveLogger atomic.Pointer[slog.Logger]
	liveLogger.Store(discardLogger())
	fw := wincoe.NewWin11SafeFileWriter(true, 1, 10, &liveLogger)

	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		_ = fw.SafeWriteFile(targetFile, []byte("data"), 0600) // nolint:errcheck // on purpose, we care only about the panic
	}()

	// Reset permissions for test cleanup
	chmodErr := os.Chmod(targetFile+wincoe.PowerlossFileExtension, 0600)
	if chmodErr != nil {
		t.Errorf("Chmod failed so cleanup will fail, err: %v", chmodErr)
	}

	if !panicked {
		t.Error("Expected catastrophic panic when Rename, Remove, and Truncate ALL fail on first boot")
	}
}

func TestWin11SafeFileWriter_Mock_ReplaceFileFails_RemoveSucceeds(t *testing.T) {
	defer restoreHooks()
	dir := t.TempDir()
	targetFile := filepath.Join(dir, "config.json")

	// Create the target file so os.IsNotExist returns false (triggers ReplaceFile path)
	wrErr := os.WriteFile(targetFile, []byte("old"), 0600)
	if wrErr != nil {
		t.Errorf("WriteFile failed so tests will fail, err: %v", wrErr)
	}

	// MOCK: ReplaceFile fails, simulating ACL issues or locked backups
	wincoe.ReplaceFileFunc = func(replaced, replacement, backup string, flags uint32) error {
		return fmt.Errorf("mock ReplaceFileW failure")
	}

	var liveLogger atomic.Pointer[slog.Logger]
	liveLogger.Store(discardLogger())
	fw := wincoe.NewWin11SafeFileWriter(true, 1, 10, &liveLogger) // 1 retry for speed

	// This should drop down to the in-place truncate fallback and succeed
	err := fw.SafeWriteFile(targetFile, []byte("new"), 0600)
	if err != nil {
		t.Fatalf("Expected fallback to succeed, got error: %v", err)
	}

	// Verify fallback wrote the data
	got, rdErr := os.ReadFile(targetFile)
	if rdErr != nil {
		t.Errorf("ReadFile failed so tests will fail, err: %v", rdErr)
	}
	if string(got) != "new" {
		t.Errorf("Fallback write failed, got %q", got)
	}
}

func TestWin11SafeFileWriter_Mock_ReplaceFileFails_RemoveFails_TruncateSucceeds(t *testing.T) {
	defer restoreHooks()
	dir := t.TempDir()
	targetFile := filepath.Join(dir, "config.json")
	wrErr := os.WriteFile(targetFile, []byte("old"), 0644)
	if wrErr != nil {
		t.Errorf("WriteFile failed so tests will fail, err: %v", wrErr)
	}

	// MOCK 1: ReplaceFile fails
	wincoe.ReplaceFileFunc = func(replaced, replacement, backup string, flags uint32) error {
		return fmt.Errorf("mock ReplaceFileW failure")
	}
	// MOCK 2: Deleting staging file fails
	wincoe.OsRemoveFunc = func(name string) error {
		return fmt.Errorf("mock os.Remove failure")
	}

	var liveLogger atomic.Pointer[slog.Logger]
	liveLogger.Store(discardLogger())
	fw := wincoe.NewWin11SafeFileWriter(true, 1, 10, &liveLogger)

	err := fw.SafeWriteFile(targetFile, []byte("new"), 0644)
	if err != nil {
		t.Fatalf("Expected fallback to succeed despite remove failure, got: %v", err)
	}

	// Because truncate succeeded, the staging file should exist but be exactly 0 bytes.
	staging := targetFile + wincoe.PowerlossFileExtension
	fi, err := os.Stat(staging)
	if err != nil {
		t.Fatalf("Staging file should still exist (remove failed): %v", err)
	}
	if fi.Size() != 0 {
		t.Errorf("Expected staging file to be truncated to 0 bytes, got %d", fi.Size())
	}
}

func TestWin11SafeFileWriter_Mock_FirstBootRenameFails(t *testing.T) {
	defer restoreHooks()
	dir := t.TempDir()
	targetFile := filepath.Join(dir, "new_config.json")

	// Target does NOT exist -> triggers initial os.Rename path

	// MOCK: Rename fails
	wincoe.OsRenameFunc = func(oldpath, newpath string) error {
		return fmt.Errorf("mock os.Rename failure")
	}

	var liveLogger atomic.Pointer[slog.Logger]
	liveLogger.Store(discardLogger())
	fw := wincoe.NewWin11SafeFileWriter(true, 1, 10, &liveLogger)

	// Rename fails -> should drop to Truncate fallback and create the file
	err := fw.SafeWriteFile(targetFile, []byte("data"), 0644)
	if err != nil {
		t.Fatalf("Expected fallback to succeed, got: %v", err)
	}

	got, rdErr := os.ReadFile(targetFile)
	if rdErr != nil {
		t.Errorf("ReadFile failed so tests will fail, err: %v", rdErr)
	}
	if string(got) != "data" {
		t.Errorf("Fallback write failed on first-boot path, got %q", got)
	}
}

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
	fw := wincoe.NewWin11SafeFileWriter(true, 6, 100, &liveLogger)

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
	powerLossFile := targetFile + wincoe.PowerlossFileExtension
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
	err = os.WriteFile(powerLossFile, []byte("interrupted partial write data"), 0600)
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
	wrErr := os.WriteFile(powerLossFile, []byte(""), 0644)
	if wrErr != nil {
		t.Errorf("WriteFile failed so tests will fail, err: %v", wrErr)
	}

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
	fw := wincoe.NewWin11SafeFileWriter(true, 6, 100, &liveLogger)

	stagingFile := targetFile + wincoe.PowerlossFileExtension

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
	fw := wincoe.NewWin11SafeFileWriter(true, 6, 100, &liveLogger)

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
	if _, err := os.Stat(targetFile + wincoe.PowerlossFileExtension); !os.IsNotExist(err) {
		t.Error("staging file left behind after concurrent writes")
	}
}

func TestSafeFileWriter_ExtraSafetyOff_NoStagingFileCreated(t *testing.T) {
	dir := t.TempDir()
	targetFile := filepath.Join(dir, "config.json")

	var liveLogger atomic.Pointer[slog.Logger]
	liveLogger.Store(slog.New(slog.NewTextHandler(io.Discard, nil)))
	fw := wincoe.NewWin11SafeFileWriter(false, 6, 100, &liveLogger)

	if err := fw.SafeWriteFile(targetFile, []byte(`{"ok":true}`), 0644); err != nil {
		t.Fatalf("SafeWriteFile failed: %v", err)
	}

	// When ExtraSafety is OFF the staging file must never appear at all.
	if _, err := os.Stat(targetFile + wincoe.PowerlossFileExtension); !os.IsNotExist(err) {
		t.Error("staging file was created despite ExtraSafety being OFF")
	}
}

func TestSafeFileWriter_SetExtraSafety_Toggle(t *testing.T) {
	dir := t.TempDir()
	targetFile := filepath.Join(dir, "config.json")

	var liveLogger atomic.Pointer[slog.Logger]
	liveLogger.Store(slog.New(slog.NewTextHandler(io.Discard, nil)))
	fw := wincoe.NewWin11SafeFileWriter(false, 6, 100, &liveLogger)

	// --- OFF → write → no staging ---
	if err := fw.SafeWriteFile(targetFile, []byte(`{"v":1}`), 0644); err != nil {
		t.Fatalf("write with ExtraSafety OFF failed: %v", err)
	}
	if _, err := os.Stat(targetFile + wincoe.PowerlossFileExtension); !os.IsNotExist(err) {
		t.Error("staging file must not exist when ExtraSafety is OFF")
	}

	// --- toggle ON → write → staging cleaned up ---
	fw.SetExtraSafety(true)
	data2 := []byte(`{"v":2}`)
	if err := fw.SafeWriteFile(targetFile, data2, 0644); err != nil {
		t.Fatalf("write with ExtraSafety ON failed: %v", err)
	}
	if _, err := os.Stat(targetFile + wincoe.PowerlossFileExtension); !os.IsNotExist(err) {
		t.Error("staging file must be cleaned up after successful write with ExtraSafety ON")
	}
	got, rdErr := os.ReadFile(targetFile)
	if rdErr != nil {
		t.Errorf("ReadFile failed so tests will fail, err: %v", rdErr)
	}
	if !bytes.Equal(got, data2) {
		t.Errorf("content mismatch after toggle: got %q, want %q", got, data2)
	}

	// --- toggle OFF again → staging must not reappear ---
	fw.SetExtraSafety(false)
	data3 := []byte(`{"v":3}`)
	if err := fw.SafeWriteFile(targetFile, data3, 0644); err != nil {
		t.Fatalf("write after second toggle failed: %v", err)
	}
	if _, err := os.Stat(targetFile + wincoe.PowerlossFileExtension); !os.IsNotExist(err) {
		t.Error("staging file must not exist after toggling ExtraSafety back OFF")
	}
}

func TestSafeFileWriter_CheckPowerLossFile_EmptyFilename(t *testing.T) {
	var liveLogger atomic.Pointer[slog.Logger]
	liveLogger.Store(slog.New(slog.NewTextHandler(io.Discard, nil)))
	fw := wincoe.NewWin11SafeFileWriter(true, 6, 100, &liveLogger)

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("CheckPowerLossFile(\"\") panicked unexpectedly: %v", r)
		}
	}()
	fw.CheckPowerLossFile("")
}

func TestWin11SafeFileWriter_PowerLossFileWithZeroBytesIsIgnored(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.json")
	staging := target + wincoe.PowerlossFileExtension

	// Create a zero-byte staging file (previous cleanup succeeded but unlink failed)
	if err := os.WriteFile(staging, nil, 0600); err != nil {
		t.Fatal(err)
	}

	var liveLogger atomic.Pointer[slog.Logger]
	liveLogger.Store(discardLogger())
	fw := wincoe.NewWin11SafeFileWriter(true, 3, 50, &liveLogger)

	// Must NOT panic
	fw.CheckPowerLossFile(target)

	// File should still exist (we only ignore it, don't delete)
	if _, err := os.Stat(staging); err != nil {
		t.Error("zero-byte staging file should still exist")
	}
}
