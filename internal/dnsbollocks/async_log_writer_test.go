//go:build windows
// +build windows

package dnsbollocks

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// syncSliceWriter is a trivial io.Writer that records every Write() call,
// guarded by its own mutex so tests can safely inspect it from the test
// goroutine while asyncLogWriter's drain goroutine is writing concurrently.
type syncSliceWriter struct {
	mu    sync.Mutex
	lines [][]byte
}

func (s *syncSliceWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]byte, len(p))
	copy(cp, p)
	s.lines = append(s.lines, cp)
	return len(p), nil
}

func (s *syncSliceWriter) snapshot() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]byte, len(s.lines))
	copy(out, s.lines)
	return out
}

// writerFunc adapts a plain function to the io.Writer interface, for tests.
type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

type closeTrackingWriter struct {
	closed bool
}

func (c *closeTrackingWriter) Write(p []byte) (int, error) { return len(p), nil }
func (c *closeTrackingWriter) Close() error                { c.closed = true; return nil }

type failingCloseWriter struct {
	err error
}

func (f *failingCloseWriter) Write(p []byte) (int, error) { return len(p), nil }
func (f *failingCloseWriter) Close() error                { return f.err }

func TestAsyncLogWriter_WritesReachUnderlyingInOrder(t *testing.T) {
	underlying := &syncSliceWriter{}
	w := newAsyncLogWriter(underlying, "test.log")

	for i := 0; i < 50; i++ {
		if _, err := w.Write([]byte{byte(i)}); err != nil {
			t.Fatalf("Write() returned unexpected error: %v", err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close() returned unexpected error: %v", err)
	}

	lines := underlying.snapshot()
	if len(lines) != 50 {
		t.Fatalf("expected 50 lines to reach the underlying writer, got %d", len(lines))
	}
	for i, line := range lines {
		if len(line) != 1 || line[0] != byte(i) {
			t.Errorf("line %d: expected [%d], got %v (ordering not preserved)", i, i, line)
		}
	}
}

func TestAsyncLogWriter_WriteNeverBlocksCallerEvenWhenUnderlyingStalls(t *testing.T) {
	blockDrain := make(chan struct{})

	blockingWriter := writerFunc(func(p []byte) (int, error) {
		<-blockDrain // simulates a stalled disk
		return len(p), nil
	})

	w := newAsyncLogWriter(blockingWriter, "test.log")
	defer func() {
		close(blockDrain)
		_ = w.Close()
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Flood well past the queue capacity; every single call must return
		// immediately regardless of the drain goroutine being stuck.
		for i := 0; i < asyncLogWriterQueueCapacity*2; i++ {
			_, _ = w.Write([]byte("x"))
		}
	}()

	select {
	case <-done:
		// success: Write() never blocked the caller
	case <-time.After(2 * time.Second):
		t.Fatal("Write() blocked the caller while the underlying writer was stalled; async logging is not actually async")
	}

	if got := w.DroppedCount(); got == 0 {
		t.Error("expected some lines to be dropped once the bounded queue filled up, got 0 dropped")
	}
}

func TestAsyncLogWriter_CloseIsIdempotentAndSafeAfterConcurrentWrite(t *testing.T) {
	underlying := &syncSliceWriter{}
	w := newAsyncLogWriter(underlying, "test.log")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_, _ = w.Write([]byte("x"))
		}
	}()

	if err := w.Close(); err != nil {
		t.Fatalf("first Close() returned unexpected error: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second Close() returned unexpected error: %v", err)
	}
	wg.Wait() // must not panic: Write() racing with Close() must never send on a closed channel

	// Writes after Close() must be silently dropped, never panic, never error.
	if _, err := w.Write([]byte("after close")); err != nil {
		t.Fatalf("Write() after Close() returned unexpected error: %v", err)
	}
}

func TestAsyncLogWriter_ClosesUnderlyingIfItImplementsIOCloser(t *testing.T) {
	underlying := &closeTrackingWriter{}
	w := newAsyncLogWriter(underlying, "test.log")

	if err := w.Close(); err != nil {
		t.Fatalf("Close() returned unexpected error: %v", err)
	}
	if !underlying.closed {
		t.Error("expected underlying io.Closer to be closed")
	}
}

func TestAsyncLogWriter_CloseReportsUnderlyingCloseError(t *testing.T) {
	sentinel := errors.New("simulated close failure")
	underlying := &failingCloseWriter{err: sentinel}
	w := newAsyncLogWriter(underlying, "test.log")

	err := w.Close()
	if err == nil {
		t.Fatal("expected Close() to return an error, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected wrapped sentinel error, got: %v", err)
	}
}