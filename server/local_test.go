package server

import (
	"context"
	"strings"
	"testing"
	"time"
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
