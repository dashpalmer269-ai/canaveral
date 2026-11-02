//go:build !windows

package runtime

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"
)

// A real SIGINT delivered to the process, as Ctrl+C would send.
func TestRealInterruptSignal(t *testing.T) {
	lc := NewLifecycle(context.Background(), time.Second)
	stop := lc.WatchSignals()
	defer stop()
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case <-lc.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("SIGINT did not trigger shutdown")
	}
}
