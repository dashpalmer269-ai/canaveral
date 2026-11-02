package runtime

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestShutdownRunsHooksOnceInReverseOrder(t *testing.T) {
	lc := NewLifecycle(context.Background(), time.Second)
	var mu sync.Mutex
	var order []string
	for _, n := range []string{"first", "second", "third"} {
		lc.OnShutdown(n, func(context.Context) error {
			mu.Lock()
			defer mu.Unlock()
			order = append(order, n)
			return nil
		})
	}
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if res := lc.Shutdown("test"); len(res) != 3 {
				t.Errorf("results %v", res)
			}
		}()
	}
	wg.Wait()
	if strings.Join(order, ",") != "third,second,first" {
		t.Fatalf("order %v", order)
	}
	if lc.Context().Err() == nil || !strings.Contains(context.Cause(lc.Context()).Error(), "test") {
		t.Fatalf("context not canceled with cause: %v", context.Cause(lc.Context()))
	}
	if lc.OnShutdown("late", func(context.Context) error { return nil }) {
		t.Fatal("hook registered after shutdown")
	}
}

func TestHookPanicAndErrorDoNotStopOtherHooks(t *testing.T) {
	lc := NewLifecycle(context.Background(), time.Second)
	ran := false
	lc.OnShutdown("cleanup", func(context.Context) error { ran = true; return nil })
	lc.OnShutdown("fails", func(context.Context) error { return errors.New("boom") })
	lc.OnShutdown("panics", func(context.Context) error { panic("hook panic") })
	res := lc.Shutdown("test")
	if !ran {
		t.Fatal("cleanup hook did not run")
	}
	if res[0].Name != "panics" || res[0].Panic != "hook panic" || res[1].Err == nil || res[2].Err != nil {
		t.Fatalf("results %+v", res)
	}
}

func TestSlowHookTimesOut(t *testing.T) {
	lc := NewLifecycle(context.Background(), 50*time.Millisecond)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	fastRan := false
	lc.OnShutdown("fast", func(context.Context) error { fastRan = true; return nil })
	lc.OnShutdown("stuck", func(context.Context) error { <-release; return nil })
	start := time.Now()
	res := lc.Shutdown("test")
	if time.Since(start) > 2*time.Second {
		t.Fatalf("shutdown took %v", time.Since(start))
	}
	if !res[0].TimedOut || !fastRan {
		t.Fatalf("results %+v fastRan=%v", res, fastRan)
	}
}

func TestGoroutinePanicTriggersShutdown(t *testing.T) {
	lc := NewLifecycle(context.Background(), time.Second)
	cleaned := make(chan struct{})
	lc.OnShutdown("cleanup", func(context.Context) error { close(cleaned); return nil })
	lc.Go("collector", func(context.Context) { panic("collector bug") })
	select {
	case <-lc.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("panic did not trigger shutdown")
	}
	<-cleaned
	p := lc.Panics()
	if len(p) != 1 || p[0].Where != "collector" || p[0].Value != "collector bug" || !strings.Contains(p[0].Stack, "goroutine") {
		t.Fatalf("panics %+v", p)
	}
	if !strings.Contains(lc.Cause(), "panic in collector") {
		t.Fatalf("cause %q", lc.Cause())
	}
}

func TestGoroutineSeesCancellation(t *testing.T) {
	lc := NewLifecycle(context.Background(), time.Second)
	stopped := make(chan struct{})
	lc.Go("worker", func(ctx context.Context) { <-ctx.Done(); close(stopped) })
	lc.Shutdown("operator quit")
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not observe cancellation")
	}
}

func TestRecoverToSetsExitCode(t *testing.T) {
	lc := NewLifecycle(context.Background(), time.Second)
	cleaned := false
	lc.OnShutdown("cleanup", func(context.Context) error { cleaned = true; return nil })
	run := func() (code int) {
		defer lc.RecoverTo(&code)
		panic("main bug")
	}
	if code := run(); code != ExitPanic || !cleaned || len(lc.Panics()) != 1 {
		t.Fatalf("code=%d cleaned=%v panics=%v", code, cleaned, lc.Panics())
	}
	if run2 := func() (code int) { defer NewLifecycle(context.Background(), 0).RecoverTo(&code); return 7 }; run2() != 7 {
		t.Fatal("RecoverTo changed the code without a panic")
	}
}

func TestSignalStartsShutdown(t *testing.T) {
	lc := NewLifecycle(context.Background(), time.Second)
	ch := make(chan os.Signal, 1)
	stop := lc.watch(ch)
	defer stop()
	ch <- os.Interrupt
	select {
	case <-lc.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("signal did not trigger shutdown")
	}
	if lc.Cause() != "signal: interrupt" {
		t.Fatalf("cause %q", lc.Cause())
	}
}

func TestStoppedWatcherIgnoresSignals(t *testing.T) {
	lc := NewLifecycle(context.Background(), time.Second)
	ch := make(chan os.Signal, 1)
	stop := lc.watch(ch)
	stop()
	stop()
	ch <- os.Interrupt
	time.Sleep(50 * time.Millisecond)
	if lc.Cause() != "" {
		t.Fatalf("stopped watcher still acted: %q", lc.Cause())
	}
}

func TestStopWatcherFromHookDoesNotDeadlock(t *testing.T) {
	lc := NewLifecycle(context.Background(), 5*time.Second)
	ch := make(chan os.Signal, 1)
	stop := lc.watch(ch)
	lc.OnShutdown("stop signals", func(context.Context) error { stop(); return nil })
	ch <- os.Interrupt
	select {
	case <-lc.Done():
	case <-time.After(time.Second):
		t.Fatal("stopping the watcher from a hook blocked shutdown")
	}
	if res := lc.Shutdown("again"); res[0].TimedOut {
		t.Fatalf("hook timed out: %+v", res)
	}
}
