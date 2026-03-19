package winrm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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

// winrmClient wraps a WinRM client to implement ssh.Client.
type winrmClient struct {
	client *gowinrm.Client
	params ssh.ConnectionParams
}

// Dial creates a new WinRM connection.
func (d *WinRMDialer) Dial(_ context.Context, params ssh.ConnectionParams) (*winrmClient, error) {
	params = withWinRMDefaults(params)

	endpoint := gowinrm.NewEndpoint(params.Host, params.Port, params.UseTLS, params.Insecure, nil, nil, nil, d.connectTimeout())

	client, err := gowinrm.NewClient(endpoint, params.User, params.Password)
	if err != nil {
		return nil, fmt.Errorf("create winrm client: %w", err)
	}

	return &winrmClient{client: client, params: params}, nil
}

func (c *winrmClient) Execute(ctx context.Context, command string, timeout time.Duration) (ssh.ExecResult, error) {
	execCtx := ctx
	cancel := func() {}
	if timeout > 0 {
		execCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	var stdout, stderr bytes.Buffer
	started := time.Now()

	exitCode, err := c.client.RunWithContext(execCtx, command, &stdout, &stderr)
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

// WinRMManager manages WinRM connections, implementing server.Executor.
type WinRMManager struct {
	mu          sync.Mutex
	dialer      *WinRMDialer
	connections map[string]*ManagedWinRMConnection
}

// NewWinRMManager creates a new WinRM connection manager.
func NewWinRMManager(dialer *WinRMDialer) *WinRMManager {
	if dialer == nil {
		dialer = &WinRMDialer{}
	}
	return &WinRMManager{
		dialer:      dialer,
		connections: make(map[string]*ManagedWinRMConnection),
	}
}

func (m *WinRMManager) Connect(ctx context.Context, params ssh.ConnectionParams) error {
	if params.Host == "" {
		return errors.New("host is required")
	}

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
