package winrm

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fawdyinc/shellguard/ssh"
)

// newTestClient returns a client whose wire call is `run`, so Execute can be
// driven without a Windows host.
func newTestClient(run runFunc) *winrmClient {
	return &winrmClient{sem: make(chan struct{}, 1), run: run}
}

// A client owns one NTLM security session, whose RC4 keystream and sequence
// numbers advance on every message and are guarded by nothing. Overlapping
// commands corrupt each other, which a live host reported as
// "parsing xml response: EOF" and "401 - invalid content type" for as long as
// parallel agents kept talking to it.
func TestExecuteNeverOverlaps(t *testing.T) {
	var inFlight, peak atomic.Int32

	client := newTestClient(func(_ context.Context, _ string, _, _ io.Writer) (int, error) {
		n := inFlight.Add(1)
		for {
			seen := peak.Load()
			if n <= seen || peak.CompareAndSwap(seen, n) {
				break
			}
		}
		time.Sleep(time.Millisecond)
		inFlight.Add(-1)
		return 0, nil
	})

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := client.Execute(context.Background(), "Get-Service", 0); err != nil {
				t.Errorf("execute: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := peak.Load(); got != 1 {
		t.Fatalf("peak concurrent commands = %d, want 1", got)
	}
}

// A command that fails must not keep the turnstile shut behind it.
func TestExecuteReleasesAfterFailure(t *testing.T) {
	client := newTestClient(func(_ context.Context, _ string, _, _ io.Writer) (int, error) {
		return 0, errors.New("winrm execute: parsing xml response: EOF")
	})

	for i := 0; i < 3; i++ {
		if _, err := client.Execute(context.Background(), "x", 0); err == nil {
			t.Fatal("expected the run error to surface")
		}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = client.Execute(context.Background(), "x", 0)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the semaphore was not released after a failed command")
	}
}

// Waiting for a turn must honour cancellation, or a cancelled request would
// sit behind a long command until that command finished.
func TestExecuteWaitRespectsCancellation(t *testing.T) {
	release := make(chan struct{})
	client := newTestClient(func(_ context.Context, _ string, _, _ io.Writer) (int, error) {
		<-release
		return 0, nil
	})

	held := make(chan struct{})
	go func() {
		close(held)
		_, _ = client.Execute(context.Background(), "slow", 0)
	}()
	<-held
	// Let the first command take the turnstile before the second queues.
	time.Sleep(20 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := client.Execute(ctx, "queued", 0)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("waited %v for a cancelled context", elapsed)
	}
	close(release)
}

// The queue must not be charged against the command's own timeout: a command
// that waited its turn still gets the time it asked for.
func TestExecuteTimeoutCoversRunNotQueue(t *testing.T) {
	firstDone := make(chan struct{})
	var ranSecond atomic.Bool

	client := newTestClient(func(ctx context.Context, command string, _, _ io.Writer) (int, error) {
		if command == "first" {
			<-firstDone
			return 0, nil
		}
		ranSecond.Store(true)
		// A deadline exists and has not already expired while queueing.
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Error("expected a deadline on the second command")
		} else if remaining := time.Until(deadline); remaining < 400*time.Millisecond {
			t.Errorf("second command kept only %v of its 500ms timeout", remaining)
		}
		return 0, nil
	})

	go func() { _, _ = client.Execute(context.Background(), "first", 0) }()
	time.Sleep(20 * time.Millisecond)

	queued := make(chan error, 1)
	go func() {
		_, err := client.Execute(context.Background(), "second", 500*time.Millisecond)
		queued <- err
	}()

	// Hold the first command well past the second's timeout.
	time.Sleep(600 * time.Millisecond)
	close(firstDone)

	if err := <-queued; err != nil {
		t.Fatalf("queued command failed: %v", err)
	}
	if !ranSecond.Load() {
		t.Fatal("the queued command never ran")
	}
}

// Several callers converging on one host must produce one handshake, not one
// each. A live host showed three racing connects, all of which failed.
func TestConnectCollapsesConcurrentCallers(t *testing.T) {
	var dials atomic.Int32
	release := make(chan struct{})

	manager := NewWinRMManager(nil)
	manager.dial = func(_ context.Context, _ ssh.ConnectionParams) error {
		dials.Add(1)
		<-release
		return nil
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = manager.Connect(context.Background(), ssh.ConnectionParams{Host: "win-1"})
		}()
	}

	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := dials.Load(); got != 1 {
		t.Fatalf("dials = %d, want 1", got)
	}
}

// Every waiter must see the outcome, not just the caller that did the dialing.
func TestConnectSharesTheFailureWithWaiters(t *testing.T) {
	release := make(chan struct{})
	wantErr := errors.New("winrm connectivity test failed: 401 - invalid content type")

	manager := NewWinRMManager(nil)
	manager.dial = func(_ context.Context, _ ssh.ConnectionParams) error {
		<-release
		return wantErr
	}

	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		go func() {
			errs <- manager.Connect(context.Background(), ssh.ConnectionParams{Host: "win-1"})
		}()
	}

	time.Sleep(50 * time.Millisecond)
	close(release)

	for i := 0; i < 4; i++ {
		if err := <-errs; !errors.Is(err, wantErr) {
			t.Fatalf("waiter %d got %v, want %v", i, err, wantErr)
		}
	}
}

// A connect that finishes must leave nothing behind, or the next attempt would
// join a dial that is already over and hang.
func TestConnectClearsTheInFlightEntry(t *testing.T) {
	manager := NewWinRMManager(nil)
	manager.dial = func(_ context.Context, _ ssh.ConnectionParams) error { return nil }

	for i := 0; i < 3; i++ {
		if err := manager.Connect(context.Background(), ssh.ConnectionParams{Host: "win-1"}); err != nil {
			t.Fatalf("connect %d: %v", i, err)
		}
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.dialing) != 0 {
		t.Fatalf("dialing map still holds %d entries", len(manager.dialing))
	}
}
