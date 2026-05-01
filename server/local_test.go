package server

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/fawdyinc/shellguard/ssh"
)

func TestLocalExecutor_Execute_Success(t *testing.T) {
	exec := NewLocalExecutor()
	res, err := exec.Execute(context.Background(), "", "echo hello", 5*time.Second)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := strings.TrimSpace(res.Stdout); got != "hello" {
		t.Fatalf("stdout = %q, want %q", got, "hello")
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", res.ExitCode)
	}
}

func TestLocalExecutor_Execute_NonZeroExit(t *testing.T) {
	exec := NewLocalExecutor()
	res, err := exec.Execute(context.Background(), "", "false", 5*time.Second)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if res.ExitCode == 0 {
		t.Fatal("expected non-zero exit code")
	}
}

func TestLocalExecutor_Execute_Stderr(t *testing.T) {
	exec := NewLocalExecutor()
	res, err := exec.Execute(context.Background(), "", "echo err >&2", 5*time.Second)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := strings.TrimSpace(res.Stderr); got != "err" {
		t.Fatalf("stderr = %q, want %q", got, "err")
	}
}

func TestLocalExecutor_Execute_Timeout(t *testing.T) {
	exec := NewLocalExecutor()
	_, err := exec.Execute(context.Background(), "", "sleep 10", 100*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestLocalExecutor_SFTPSession_Error(t *testing.T) {
	exec := NewLocalExecutor()
	_, err := exec.SFTPSession("any")
	if err == nil {
		t.Fatal("expected error from SFTPSession")
	}
}

func requireBash(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on PATH")
	}
}

// TestLocalExecutor_Persistent_RoundTrip confirms that a Connect-spawned bash
// session executes commands through the persistent PTY and preserves shell
// state across calls (the cd in the first command is visible to the second).
func TestLocalExecutor_Persistent_RoundTrip(t *testing.T) {
	requireBash(t)
	le := NewLocalExecutor()
	ctx := context.Background()

	if err := le.Connect(ctx, ssh.ConnectionParams{Host: "local:1", Command: "bash"}); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = le.Disconnect(ctx, "local:1") })

	res, err := le.Execute(ctx, "local:1", "echo hello-pty", 5*time.Second)
	if err != nil {
		t.Fatalf("Execute(echo) error = %v", err)
	}
	if got := strings.TrimSpace(res.Stdout); got != "hello-pty" {
		t.Fatalf("stdout = %q, want %q", got, "hello-pty")
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit = %d, want 0", res.ExitCode)
	}

	if _, err := le.Execute(ctx, "local:1", "cd /tmp", 5*time.Second); err != nil {
		t.Fatalf("Execute(cd) error = %v", err)
	}
	res, err = le.Execute(ctx, "local:1", "pwd", 5*time.Second)
	if err != nil {
		t.Fatalf("Execute(pwd) error = %v", err)
	}
	if got := strings.TrimSpace(res.Stdout); got != "/tmp" {
		t.Fatalf("pwd after cd = %q, want /tmp (state should persist across execs)", got)
	}
}

// TestLocalExecutor_Persistent_NonZeroExit verifies the sentinel protocol
// recovers a non-zero exit status from the PTY-spawned shell.
func TestLocalExecutor_Persistent_NonZeroExit(t *testing.T) {
	requireBash(t)
	le := NewLocalExecutor()
	ctx := context.Background()

	if err := le.Connect(ctx, ssh.ConnectionParams{Host: "local:exit", Command: "bash"}); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	t.Cleanup(func() { _ = le.Disconnect(ctx, "local:exit") })

	res, err := le.Execute(ctx, "local:exit", "false", 5*time.Second)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if res.ExitCode == 0 {
		t.Fatalf("expected non-zero exit, got 0")
	}
}

// TestLocalExecutor_Persistent_ConnectFailure confirms that spawn failures
// (e.g. "command not found") surface as a Connect error rather than silently
// succeeding and failing later on Execute.
func TestLocalExecutor_Persistent_ConnectFailure(t *testing.T) {
	requireBash(t)
	le := NewLocalExecutor()
	ctx := context.Background()

	err := le.Connect(ctx, ssh.ConnectionParams{
		Host:    "local:dead",
		Command: "this-binary-does-not-exist-shellguard-test",
	})
	if err == nil {
		_ = le.Disconnect(ctx, "local:dead")
		t.Fatal("expected Connect to fail when spawned command is missing")
	}
}

// TestLocalExecutor_Persistent_Disconnect tears down the PTY-spawned subprocess
// and verifies subsequent Execute falls back to the stateless `sh -c` path
// (so it still succeeds, but the prior session's state is gone).
func TestLocalExecutor_Persistent_Disconnect(t *testing.T) {
	requireBash(t)
	le := NewLocalExecutor()
	ctx := context.Background()

	if err := le.Connect(ctx, ssh.ConnectionParams{Host: "local:bye", Command: "bash"}); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	if _, err := le.Execute(ctx, "local:bye", "X=hello", 5*time.Second); err != nil {
		t.Fatalf("Execute(set X) error = %v", err)
	}

	if err := le.Disconnect(ctx, "local:bye"); err != nil {
		t.Fatalf("Disconnect() error = %v", err)
	}

	// After disconnect the session is gone — Execute should fall back to a
	// fresh `sh -c` shell which has no knowledge of $X.
	res, err := le.Execute(ctx, "local:bye", "echo \"X=$X\"", 5*time.Second)
	if err != nil {
		t.Fatalf("Execute(after disconnect) error = %v", err)
	}
	if got := strings.TrimSpace(res.Stdout); got != "X=" {
		t.Fatalf("stdout = %q, want %q (session state should be gone)", got, "X=")
	}
}

// TestLocalExecutor_Persistent_DisconnectAll clears every active session.
func TestLocalExecutor_Persistent_DisconnectAll(t *testing.T) {
	requireBash(t)
	le := NewLocalExecutor()
	ctx := context.Background()

	for _, host := range []string{"local:a", "local:b"} {
		if err := le.Connect(ctx, ssh.ConnectionParams{Host: host, Command: "bash"}); err != nil {
			t.Fatalf("Connect(%s) error = %v", host, err)
		}
	}

	if err := le.Disconnect(ctx, ""); err != nil {
		t.Fatalf("Disconnect(all) error = %v", err)
	}

	le.mu.Lock()
	remaining := len(le.sessions)
	le.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("expected 0 sessions after Disconnect(all), got %d", remaining)
	}
}

// TestLocalExecutor_Persistent_Stateless confirms Connect with no Command
// preserves the legacy stateless behaviour (each Execute spawns a fresh
// `sh -c` and stdout/stderr stay separate).
func TestLocalExecutor_Persistent_Stateless(t *testing.T) {
	le := NewLocalExecutor()
	ctx := context.Background()

	if err := le.Connect(ctx, ssh.ConnectionParams{Host: "local:stateless"}); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	res, err := le.Execute(ctx, "local:stateless", "echo out; echo err >&2", 5*time.Second)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := strings.TrimSpace(res.Stdout); got != "out" {
		t.Fatalf("stdout = %q, want %q", got, "out")
	}
	if got := strings.TrimSpace(res.Stderr); got != "err" {
		t.Fatalf("stderr = %q, want %q (stateless mode should keep streams split)", got, "err")
	}
}
