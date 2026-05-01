package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/fawdyinc/shellguard/ssh"
)

// LocalExecutor runs commands on the local machine.
//
// In stateless mode (Connect called without a Command), each Execute spawns
// a fresh `sh -c <command>` subprocess.
//
// In persistent mode (Connect called with a Command), the Command is spawned
// once under a PTY (via `sh -c <command>`) and held open for the lifetime of
// the connection. Each Execute writes the user's command to that PTY,
// bracketed by a per-session sentinel that lets us detect the end of output
// and the exit status. Disconnect tears down the subprocess.
type LocalExecutor struct {
	mu       sync.Mutex
	sessions map[string]*localSession
}

// NewLocalExecutor returns a new LocalExecutor.
func NewLocalExecutor() *LocalExecutor {
	return &LocalExecutor{sessions: make(map[string]*localSession)}
}

type localSession struct {
	cmd      *exec.Cmd
	ptmx     *os.File
	sentinel string

	// mu serializes concurrent Execute calls on the same session.
	mu sync.Mutex

	// readCh streams bytes read from the PTY master. Closed when the reader
	// goroutine exits.
	readCh  chan []byte
	readErr error // set before readCh is closed

	// accum holds bytes that have been read from readCh but not yet consumed
	// by a sentinel scan. Owned by the holder of mu.
	accum []byte

	// exited is closed once cmd.Wait returns.
	exited  chan struct{}
	waitErr error
}

func (l *LocalExecutor) Connect(ctx context.Context, params ssh.ConnectionParams) error {
	if strings.TrimSpace(params.Command) == "" {
		// Stateless mode: nothing to spawn at connect time.
		return nil
	}

	sentinel, err := newSentinel()
	if err != nil {
		return fmt.Errorf("local connect: generate sentinel: %w", err)
	}

	cmd := exec.Command("sh", "-c", params.Command)
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("local connect: spawn %q: %w", params.Command, err)
	}

	sess := &localSession{
		cmd:      cmd,
		ptmx:     ptmx,
		sentinel: sentinel,
		readCh:   make(chan []byte, 16),
		exited:   make(chan struct{}),
	}

	go sess.readLoop()
	go func() {
		sess.waitErr = cmd.Wait()
		close(sess.exited)
	}()

	// Quiet the remote shell and emit a ready marker. The marker is built by
	// interpolating the per-session token (held in the shell variable __SGM)
	// so the rendered marker bytes only appear in the shell's *output*, never
	// in the kernel-echoed input line — eliminating false positives when echo
	// is still on at init time.
	initLine := fmt.Sprintf(
		"__SGM=%s; stty -echo -onlcr 2>/dev/null; PS1='' PS2='' PROMPT_COMMAND=''; printf '%%s\\n' \"${__SGM}INIT${__SGM}\"\n",
		sentinel,
	)
	if _, err := ptmx.Write([]byte(initLine)); err != nil {
		sess.terminate()
		return fmt.Errorf("local connect: write init: %w", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if _, err := sess.consumeUntil([]byte(sentinel+"INIT"+sentinel), deadline); err != nil {
		captured := strings.TrimSpace(string(sess.accum))
		sess.terminate()
		return fmt.Errorf("local connect: %w (output: %s)", err, captured)
	}

	l.mu.Lock()
	if old := l.sessions[params.Host]; old != nil {
		old.terminate()
	}
	l.sessions[params.Host] = sess
	l.mu.Unlock()

	return nil
}

func (l *LocalExecutor) Execute(ctx context.Context, host, command string, timeout time.Duration) (ssh.ExecResult, error) {
	if sess := l.getSession(host); sess != nil {
		return sess.execute(ctx, command, timeout)
	}
	return l.runStateless(ctx, command, timeout)
}

func (l *LocalExecutor) ExecuteRaw(ctx context.Context, host, command string, timeout time.Duration) (ssh.ExecResult, error) {
	return l.Execute(ctx, host, command, timeout)
}

func (l *LocalExecutor) SFTPSession(_ string) (ssh.SFTPClient, error) {
	return nil, errors.New("SFTP is not supported for local transport")
}

func (l *LocalExecutor) Disconnect(_ context.Context, host string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if host == "" {
		for h, sess := range l.sessions {
			sess.terminate()
			delete(l.sessions, h)
		}
		return nil
	}

	sess, ok := l.sessions[host]
	if !ok {
		return nil
	}
	sess.terminate()
	delete(l.sessions, host)
	return nil
}

func (l *LocalExecutor) getSession(host string) *localSession {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sessions[host]
}

func (s *localSession) execute(ctx context.Context, command string, timeout time.Duration) (ssh.ExecResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	select {
	case <-s.exited:
		return ssh.ExecResult{}, errors.New("local subprocess has exited")
	default:
	}

	deadline := time.Now().Add(timeout)
	if timeout <= 0 {
		deadline = time.Now().Add(30 * time.Second)
	}
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}

	// The user's command runs first; a follow-up printf brackets its output
	// with the per-session sentinel and the exit code. The sentinel is
	// interpolated from __SGM so its rendered bytes never appear in any
	// echoed input — only in the shell's actual output.
	line := fmt.Sprintf(
		"%s\nprintf '\\n%%s\\n' \"${__SGM}END$?${__SGM}\"\n",
		command,
	)

	started := time.Now()
	if _, err := s.ptmx.Write([]byte(line)); err != nil {
		return ssh.ExecResult{}, fmt.Errorf("local execute: write: %w", err)
	}

	output, err := s.consumeUntil([]byte(s.sentinel+"END"), deadline)
	if err != nil {
		s.terminate()
		return ssh.ExecResult{}, fmt.Errorf("local execute: %w", err)
	}
	exitCodeBytes, err := s.consumeUntil([]byte(s.sentinel), deadline)
	if err != nil {
		s.terminate()
		return ssh.ExecResult{}, fmt.Errorf("local execute: parse exit: %w", err)
	}

	exitCode, err := strconv.Atoi(strings.TrimSpace(string(exitCodeBytes)))
	if err != nil {
		s.terminate()
		return ssh.ExecResult{}, fmt.Errorf("local execute: parse exit code %q: %w", string(exitCodeBytes), err)
	}

	stdout := stripCR(output)
	// printf prepends a leading '\n' so the marker never abuts user output;
	// trim that single newline back off.
	stdout = bytes.TrimSuffix(stdout, []byte("\n"))

	return ssh.ExecResult{
		Stdout:    string(stdout),
		Stderr:    "",
		ExitCode:  exitCode,
		RuntimeMs: int(time.Since(started).Milliseconds()),
	}, nil
}

// consumeUntil pulls bytes from the session's read channel into the
// accumulator until marker is found. Returns the bytes preceding marker and
// removes them (and the marker itself) from the accumulator. Returns an
// error on deadline, subprocess exit, or read failure.
func (s *localSession) consumeUntil(marker []byte, deadline time.Time) ([]byte, error) {
	for {
		if i := bytes.Index(s.accum, marker); i >= 0 {
			out := append([]byte(nil), s.accum[:i]...)
			s.accum = append(s.accum[:0], s.accum[i+len(marker):]...)
			return out, nil
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, errors.New("read timeout waiting for sentinel")
		}
		timer := time.NewTimer(remaining)
		select {
		case data, ok := <-s.readCh:
			timer.Stop()
			if !ok {
				if s.readErr != nil && !errors.Is(s.readErr, io.EOF) {
					return nil, fmt.Errorf("pty read failed: %w", s.readErr)
				}
				return nil, errors.New("local subprocess closed pty before sentinel")
			}
			s.accum = append(s.accum, data...)
		case <-timer.C:
			return nil, errors.New("read timeout waiting for sentinel")
		case <-s.exited:
			timer.Stop()
			// Drain any remaining queued chunks, then make one last scan.
			for {
				select {
				case data, ok := <-s.readCh:
					if !ok {
						if i := bytes.Index(s.accum, marker); i >= 0 {
							out := append([]byte(nil), s.accum[:i]...)
							s.accum = append(s.accum[:0], s.accum[i+len(marker):]...)
							return out, nil
						}
						return nil, errors.New("local subprocess exited before sentinel")
					}
					s.accum = append(s.accum, data...)
				default:
					if i := bytes.Index(s.accum, marker); i >= 0 {
						out := append([]byte(nil), s.accum[:i]...)
						s.accum = append(s.accum[:0], s.accum[i+len(marker):]...)
						return out, nil
					}
					return nil, errors.New("local subprocess exited before sentinel")
				}
			}
		}
	}
}

// readLoop runs for the lifetime of the session, copying bytes from the PTY
// master into readCh. It exits (closing readCh) when Read returns an error,
// which happens when the subprocess closes its end or terminate() closes the
// master fd.
func (s *localSession) readLoop() {
	defer close(s.readCh)
	chunk := make([]byte, 4096)
	for {
		n, err := s.ptmx.Read(chunk)
		if n > 0 {
			cp := make([]byte, n)
			copy(cp, chunk[:n])
			s.readCh <- cp
		}
		if err != nil {
			s.readErr = err
			return
		}
	}
}

func (s *localSession) terminate() {
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Signal(syscall.SIGTERM)
	}
	if s.ptmx != nil {
		_ = s.ptmx.Close()
	}
	if s.exited != nil {
		select {
		case <-s.exited:
		case <-time.After(500 * time.Millisecond):
			if s.cmd != nil && s.cmd.Process != nil {
				_ = s.cmd.Process.Kill()
			}
			<-s.exited
		}
	}
}

func stripCR(b []byte) []byte {
	return bytes.ReplaceAll(b, []byte("\r"), nil)
}

func newSentinel() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "__SG_" + hex.EncodeToString(b) + "__", nil
}

// runStateless implements the legacy per-call `sh -c <command>` behaviour
// used when no persistent session has been established for the host.
func (l *LocalExecutor) runStateless(ctx context.Context, command string, timeout time.Duration) (ssh.ExecResult, error) {
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
