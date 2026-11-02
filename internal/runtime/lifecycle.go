package runtime

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	stdruntime "runtime"
	"sync"
	"syscall"
	"time"
)

// DefaultShutdownTimeout bounds how long shutdown hooks may run in total.
const DefaultShutdownTimeout = 5 * time.Second

// Exit codes.
const (
	ExitOK          = 0
	ExitError       = 1
	ExitInterrupted = 130
	ExitPanic       = 3
)

// HookResult records how one shutdown hook ended.
type HookResult struct {
	Name     string
	Err      error
	Panic    any
	TimedOut bool
}

// PanicRecord is a recovered panic.
type PanicRecord struct {
	Where string
	Value any
	Stack string
	At    time.Time
}

type hook struct {
	name string
	fn   func(context.Context) error
}

// Lifecycle coordinates cancellation and cleanup on every exit path: normal
// return, recovered panic and signal. Shutdown hooks run exactly once, in
// reverse registration order.
type Lifecycle struct {
	ctx     context.Context
	cancel  context.CancelCauseFunc
	timeout time.Duration

	mu      sync.Mutex
	hooks   []hook
	panics  []PanicRecord
	results []HookResult
	cause   string
	started bool

	once     sync.Once
	stopping chan struct{} // closed when shutdown starts
	done     chan struct{} // closed when shutdown hooks have finished
}

// NewLifecycle returns a lifecycle whose context is derived from parent.
// timeout <= 0 means DefaultShutdownTimeout.
func NewLifecycle(parent context.Context, timeout time.Duration) *Lifecycle {
	if timeout <= 0 {
		timeout = DefaultShutdownTimeout
	}
	ctx, cancel := context.WithCancelCause(parent)
	return &Lifecycle{ctx: ctx, cancel: cancel, timeout: timeout, stopping: make(chan struct{}), done: make(chan struct{})}
}

// Context is canceled as soon as shutdown begins. Collectors watch it.
func (l *Lifecycle) Context() context.Context { return l.ctx }

// Done is closed when shutdown hooks have finished.
func (l *Lifecycle) Done() <-chan struct{} { return l.done }

// OnShutdown registers a hook. It returns false, and the hook is not
// registered, if shutdown has already started.
func (l *Lifecycle) OnShutdown(name string, fn func(context.Context) error) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.started {
		return false
	}
	l.hooks = append(l.hooks, hook{name: name, fn: fn})
	return true
}

// Shutdown cancels the context and runs the hooks, newest first, within the
// lifecycle's total timeout. It is safe to call more than once and from several goroutines;
// only the first call runs hooks, and every call waits for them to finish.
func (l *Lifecycle) Shutdown(cause string) []HookResult {
	l.once.Do(func() {
		l.mu.Lock()
		l.cause, l.started = cause, true
		hooks := append([]hook(nil), l.hooks...)
		l.mu.Unlock()
		close(l.stopping)

		l.cancel(fmt.Errorf("shutdown: %s", cause))

		// Each hook gets an equal share of the time that is left, so one stuck
		// hook cannot starve the hooks after it (the earliest-registered,
		// such as cleanup, run last). The total stays within l.timeout.
		end := time.Now().Add(l.timeout)
		var results []HookResult
		for i := len(hooks) - 1; i >= 0; i-- {
			share := time.Until(end) / time.Duration(i+1)
			hctx, cancel := context.WithTimeout(context.Background(), share)
			results = append(results, runHook(hctx, hooks[i]))
			cancel()
		}
		l.mu.Lock()
		l.results = results
		l.mu.Unlock()
		close(l.done)
	})
	<-l.done
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]HookResult(nil), l.results...)
}

func runHook(ctx context.Context, h hook) HookResult {
	res := HookResult{Name: h.name}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		defer func() {
			if p := recover(); p != nil {
				res.Panic = p
			}
		}()
		res.Err = h.fn(ctx)
	}()
	select {
	case <-finished:
		return res
	case <-ctx.Done():
		return HookResult{Name: h.name, TimedOut: true, Err: ctx.Err()}
	}
}

// Cause returns the reason shutdown started, or "" if it has not.
func (l *Lifecycle) Cause() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.cause
}

// Panics returns recovered panics.
func (l *Lifecycle) Panics() []PanicRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]PanicRecord(nil), l.panics...)
}

func (l *Lifecycle) recordPanic(where string, p any) {
	buf := make([]byte, 64<<10)
	buf = buf[:stdruntime.Stack(buf, false)]
	l.mu.Lock()
	l.panics = append(l.panics, PanicRecord{Where: where, Value: p, Stack: string(buf), At: time.Now().UTC()})
	l.mu.Unlock()
}

// Go runs fn in a goroutine. A panic in fn is recovered, recorded, and starts
// shutdown, so cleanup still runs.
func (l *Lifecycle) Go(name string, fn func(ctx context.Context)) {
	go func() {
		defer func() {
			if p := recover(); p != nil {
				l.recordPanic(name, p)
				l.Shutdown(fmt.Sprintf("panic in %s: %v", name, p))
			}
		}()
		fn(l.ctx)
	}()
}

// RecoverTo is deferred in main: on panic it records the panic, runs
// shutdown, and sets *code to ExitPanic instead of crashing.
//
//	func run() (code int) {
//	    defer lc.RecoverTo(&code)
//	    ...
//	}
func (l *Lifecycle) RecoverTo(code *int) {
	if p := recover(); p != nil {
		l.recordPanic("main", p)
		l.Shutdown(fmt.Sprintf("panic in main: %v", p))
		*code = ExitPanic
	}
}

// WatchSignals starts shutdown on os.Interrupt (Ctrl+C) or SIGTERM. On
// Windows, Go delivers console close, logoff and shutdown events as SIGTERM.
// The returned function stops watching.
func (l *Lifecycle) WatchSignals() (stop func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	stopWatch := l.watch(ch)
	return func() {
		signal.Stop(ch)
		stopWatch()
	}
}

func (l *Lifecycle) watch(ch <-chan os.Signal) (stop func()) {
	quit := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		select {
		case <-quit:
			return
		default:
		}
		select {
		case sig := <-ch:
			l.Shutdown("signal: " + sig.String())
		case <-quit:
		case <-l.done:
		}
	}()
	var once sync.Once
	// stop waits for the watcher to exit, so once it returns no later signal
	// can start shutdown. If shutdown has already started (stop may be called
	// from a hook), a signal can no longer change anything, so it does not wait.
	return func() {
		once.Do(func() { close(quit) })
		select {
		case <-exited:
		case <-l.stopping:
		}
	}
}
