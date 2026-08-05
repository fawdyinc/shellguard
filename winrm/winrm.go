package winrm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/fawdyinc/shellguard/ssh"
	gowinrm "github.com/masterzen/winrm"
)

// WinRMDialer creates WinRM connections.
type WinRMDialer struct {
	ConnectTimeout time.Duration
}

func (d *WinRMDialer) connectTimeout() time.Duration {
	if d.ConnectTimeout > 0 {
		return d.ConnectTimeout
	}
	return 10 * time.Second
}

// runFunc is the single wire call a command makes. It is a field rather than a
// direct method call so the serialisation below can be exercised without a
// live Windows host.
type runFunc func(ctx context.Context, command string, stdout, stderr io.Writer) (int, error)

// winrmClient wraps a WinRM client to implement ssh.Client.
type winrmClient struct {
	// Commands on one client must not overlap.
	//
	// A client owns exactly one NTLM security session, and that session
	// carries a running RC4 keystream plus a sequence number per direction
	// (bodgit/ntlmssp security.go). Wrap and Unwrap advance both, and neither
	// masterzen/winrm nor bodgit/ntlmssp locks anything. Two commands in
	// flight therefore corrupt each other's encryption: the decrypt produces
	// unparseable XML, reported as "parsing xml response: EOF", and the
	// signature stops verifying, so Windows answers "401 - invalid content
	// type".
	//
	// Seen against a live host as soon as parallel subagents shared one
	// connection — five seconds of alternating EOF and 401 from a server that
	// was healthy throughout.
	//
	// A buffered channel rather than a sync.Mutex, because a command waiting
	// its turn must still honour cancellation.
	sem chan struct{}

	client *gowinrm.Client
	run    runFunc
	params ssh.ConnectionParams
}

// Dial creates a new WinRM connection.
func (d *WinRMDialer) Dial(_ context.Context, params ssh.ConnectionParams) (*winrmClient, error) {
	params = withWinRMDefaults(params)

	endpoint := gowinrm.NewEndpoint(params.Host, params.Port, params.UseTLS, params.Insecure, nil, nil, nil, d.connectTimeout())

	clientParams := gowinrm.NewParameters("PT60S", "en-US", 153600)
	clientParams.TransportDecorator = func() gowinrm.Transporter {
		// Over HTTP, Windows (Win10+/Server 2019+) requires WinRM message-level
		// encryption with NTLM. Over HTTPS, the TLS channel already provides
		// confidentiality, so plain ClientNTLM is sufficient.
		if params.UseTLS {
			return &gowinrm.ClientNTLM{}
		}
		enc, err := gowinrm.NewEncryption("ntlm")
		if err != nil {
			return &gowinrm.ClientNTLM{}
		}
		return enc
	}

	client, err := gowinrm.NewClientWithParameters(endpoint, params.User, params.Password, clientParams)
	if err != nil {
		return nil, fmt.Errorf("create winrm client: %w", err)
	}

	return &winrmClient{
		sem:    make(chan struct{}, 1),
		client: client,
		run:    client.RunWithContext,
		params: params,
	}, nil
}

func (c *winrmClient) Execute(ctx context.Context, command string, timeout time.Duration) (ssh.ExecResult, error) {
	// Take a turn before starting the clock. `timeout` is how long the command
	// may run, not how long it may queue behind other commands, so charging it
	// for the wait would make a busy host look like a slow one. Cancelling the
	// request still releases a waiter immediately.
	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		return ssh.ExecResult{}, ctx.Err()
	}
	defer func() { <-c.sem }()

	execCtx := ctx
	cancel := func() {}
	if timeout > 0 {
		execCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	var stdout, stderr bytes.Buffer
	started := time.Now()

	exitCode, err := c.run(execCtx, command, &stdout, &stderr)
	runtime := int(time.Since(started).Milliseconds())

	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return ssh.ExecResult{}, err
		}
		return ssh.ExecResult{}, fmt.Errorf("winrm execute: %w", err)
	}

	return ssh.ExecResult{
		Stdout:    stdout.String(),
		Stderr:    stderr.String(),
		ExitCode:  exitCode,
		RuntimeMs: runtime,
	}, nil
}

func (c *winrmClient) Close() error {
	// WinRM connections are stateless per-request; no persistent connection to close.
	return nil
}

func (c *winrmClient) SFTPSession() (ssh.SFTPClient, error) {
	return NewWinRMFileClient(c), nil
}

// ManagedWinRMConnection tracks a WinRM connection.
type ManagedWinRMConnection struct {
	Client *winrmClient
	Params ssh.ConnectionParams
}

// dialAttempt lets callers that arrive during a connect wait for its result
// instead of starting their own.
type dialAttempt struct {
	done chan struct{}
	err  error
}

// WinRMManager manages WinRM connections, implementing server.Executor.
type WinRMManager struct {
	mu          sync.Mutex
	dialer      *WinRMDialer
	connections map[string]*ManagedWinRMConnection
	dialing     map[string]*dialAttempt

	// dial performs one connection attempt. A field rather than a direct
	// method call so the single-flight in Connect can be exercised without a
	// live Windows host.
	dial func(ctx context.Context, params ssh.ConnectionParams) error
}

// NewWinRMManager creates a new WinRM connection manager.
func NewWinRMManager(dialer *WinRMDialer) *WinRMManager {
	if dialer == nil {
		dialer = &WinRMDialer{}
	}
	m := &WinRMManager{
		dialer:      dialer,
		connections: make(map[string]*ManagedWinRMConnection),
		dialing:     make(map[string]*dialAttempt),
	}
	m.dial = m.dialOnce
	return m
}

// Connect establishes a connection, or joins one already being established.
//
// Callers converge on a host at the same moment — several agents reacting to
// the same failure, say — and each used to open its own NTLM handshake and
// overwrite the map entry the others had just written. That cost seconds per
// caller and left orphaned clients behind. Now the first caller dials and the
// rest wait for its result.
func (m *WinRMManager) Connect(ctx context.Context, params ssh.ConnectionParams) error {
	if params.Host == "" {
		return errors.New("host is required")
	}

	m.mu.Lock()
	if attempt := m.dialing[params.Host]; attempt != nil {
		m.mu.Unlock()
		select {
		case <-attempt.done:
			return attempt.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	attempt := &dialAttempt{done: make(chan struct{})}
	m.dialing[params.Host] = attempt
	m.mu.Unlock()

	err := m.dial(ctx, params)

	attempt.err = err
	close(attempt.done)
	m.mu.Lock()
	delete(m.dialing, params.Host)
	m.mu.Unlock()

	return err
}

func (m *WinRMManager) dialOnce(ctx context.Context, params ssh.ConnectionParams) error {
	client, err := m.dialer.Dial(ctx, params)
	if err != nil {
		return fmt.Errorf("connect %s:%d failed: %w", params.Host, params.Port, err)
	}

	// Verify connectivity with a simple test command.
	testResult, err := client.Execute(ctx, WrapForWinRM("Write-Output 'ok'"), 10*time.Second)
	if err != nil {
		return fmt.Errorf("winrm connectivity test failed: %w", err)
	}
	if !strings.Contains(testResult.Stdout, "ok") {
		return fmt.Errorf("winrm connectivity test failed: unexpected output %q", testResult.Stdout)
	}

	m.mu.Lock()
	if old := m.connections[params.Host]; old != nil {
		_ = old.Client.Close()
	}
	m.connections[params.Host] = &ManagedWinRMConnection{Client: client, Params: params}
	m.mu.Unlock()

	return nil
}

func (m *WinRMManager) resolveConnection(host string) (*ManagedWinRMConnection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if host != "" {
		conn := m.connections[host]
		if conn == nil {
			return nil, fmt.Errorf("not connected to host %q", host)
		}
		return conn, nil
	}

	if len(m.connections) == 0 {
		return nil, errors.New("not connected")
	}
	if len(m.connections) > 1 {
		return nil, errors.New("host is required when multiple connections are active")
	}
	for _, conn := range m.connections {
		return conn, nil
	}
	return nil, errors.New("not connected")
}

func (m *WinRMManager) Execute(ctx context.Context, host, command string, timeout time.Duration) (ssh.ExecResult, error) {
	conn, err := m.resolveConnection(host)
	if err != nil {
		return ssh.ExecResult{}, err
	}
	return conn.Client.Execute(ctx, command, timeout)
}

func (m *WinRMManager) ExecuteRaw(ctx context.Context, host, command string, timeout time.Duration) (ssh.ExecResult, error) {
	return m.Execute(ctx, host, command, timeout)
}

func (m *WinRMManager) SFTPSession(host string) (ssh.SFTPClient, error) {
	conn, err := m.resolveConnection(host)
	if err != nil {
		return nil, err
	}
	return conn.Client.SFTPSession()
}

func (m *WinRMManager) Disconnect(_ context.Context, host string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if host == "" {
		for h, conn := range m.connections {
			_ = conn.Client.Close()
			delete(m.connections, h)
		}
		return nil
	}

	conn := m.connections[host]
	if conn == nil {
		return nil
	}
	_ = conn.Client.Close()
	delete(m.connections, host)
	return nil
}

func withWinRMDefaults(params ssh.ConnectionParams) ssh.ConnectionParams {
	if params.User == "" {
		params.User = "Administrator"
	}
	if params.Port == 0 {
		if params.UseTLS {
			params.Port = 5986
		} else {
			params.Port = 5985
		}
	}
	return params
}
