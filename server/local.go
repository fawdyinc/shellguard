package server

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"time"

	"github.com/fawdyinc/shellguard/ssh"
)

// LocalExecutor runs commands on the local machine.
type LocalExecutor struct{}

// NewLocalExecutor returns a new LocalExecutor.
func NewLocalExecutor() *LocalExecutor {
	return &LocalExecutor{}
}

func (l *LocalExecutor) Connect(_ context.Context, _ ssh.ConnectionParams) error {
	return nil
}

func (l *LocalExecutor) Execute(ctx context.Context, _, command string, timeout time.Duration) (ssh.ExecResult, error) {
	return l.run(ctx, command, timeout)
}

func (l *LocalExecutor) ExecuteRaw(ctx context.Context, _, command string, timeout time.Duration) (ssh.ExecResult, error) {
	return l.run(ctx, command, timeout)
}

func (l *LocalExecutor) SFTPSession(_ string) (ssh.SFTPClient, error) {
	return nil, errors.New("SFTP is not supported for local transport")
}

func (l *LocalExecutor) Disconnect(_ context.Context, _ string) error {
	return nil
}

func (l *LocalExecutor) run(ctx context.Context, command string, timeout time.Duration) (ssh.ExecResult, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	start := time.Now()
	cmd := exec.CommandContext(ctx, "sh", "-c", command)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	runtimeMs := int(time.Since(start).Milliseconds())

	if ctx.Err() != nil {
		return ssh.ExecResult{}, ctx.Err()
	}

	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			return ssh.ExecResult{}, err
		}
	}

	return ssh.ExecResult{
		Stdout:    stdout.String(),
		Stderr:    stderr.String(),
		ExitCode:  exitCode,
		RuntimeMs: runtimeMs,
	}, nil
}
