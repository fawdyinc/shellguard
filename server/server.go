// Package server wires together the security pipeline and registers MCP tools.
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fawdyinc/shellguard/manifest"
	"github.com/fawdyinc/shellguard/output"
	"github.com/fawdyinc/shellguard/parser"
	"github.com/fawdyinc/shellguard/ssh"
	"github.com/fawdyinc/shellguard/toolkit"
	"github.com/fawdyinc/shellguard/validator"
	winrmPkg "github.com/fawdyinc/shellguard/winrm"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	maxDownloadBytes   = 50 * 1024 * 1024
	defaultDownloadDir = "/tmp/shellguard-downloads"
)

// maxCollisionRetries is the upper bound on filename collision retries in
// collisionSafePath. A var (not const) so tests can temporarily lower it.
var maxCollisionRetries = 10000

// Executor runs commands on remote targets.
type Executor interface {
	Connect(ctx context.Context, params ssh.ConnectionParams) error
	Execute(ctx context.Context, host, command string, timeout time.Duration) (ssh.ExecResult, error)
	ExecuteRaw(ctx context.Context, host, command string, timeout time.Duration) (ssh.ExecResult, error)
	SFTPSession(host string) (ssh.SFTPClient, error)
	Disconnect(ctx context.Context, host string) error
}

// TransportType identifies how a server connection is established.
type TransportType string

const (
	TransportSSH   TransportType = "ssh"
	TransportLocal TransportType = "local"
	TransportWinRM TransportType = "winrm"
)

// ShellType identifies the shell dialect used by a connection.
type ShellType string

const (
	ShellBash       ShellType = "bash"
	ShellPowerShell ShellType = "powershell"
)

// ServerEntry tracks the state of a connected server.
type ServerEntry struct {
	Transport TransportType
	Shell     ShellType
	Connected bool
}

type ValidateInput struct {
	Command string `json:"command" jsonschema:"Shell command or pipeline to validate"`
}

type ValidateResult struct {
	OK      bool   `json:"ok"`
	Reason  string `json:"reason,omitempty"`
	Command string `json:"command,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

type StatusInput struct{}

type ServerStatus struct {
	Connected bool          `json:"connected"`
	Transport TransportType `json:"transport"`
	Shell     ShellType     `json:"shell"`
}

type StatusResult map[string]ServerStatus

type ProbeResult struct {
	Missing []string
	Arch    string
}

type Core struct {
	Registry    map[string]*manifest.Manifest
	Runner      Executor
	LocalRunner Executor
	WinRMRunner Executor

	Parse       func(string) (*parser.Pipeline, error)
	Validate    func(*parser.Pipeline, map[string]*manifest.Manifest) error
	Reconstruct func(*parser.Pipeline, bool, bool) string
	Truncate    func(string, string, int, int, ...int) output.CommandResult

	ParsePS       func(string) (*parser.Pipeline, error)
	ReconstructPS func(*parser.Pipeline) string

	DefaultTimeout   int
	MaxOutputBytes   int
	MaxDownloadBytes int
	DownloadDir      string
	MaxSleepSeconds  int
	DisabledTools    map[string]bool

	logger          *slog.Logger
	mu              sync.RWMutex
	probeState      map[string]*ProbeResult
	toolkitDeployed map[string]bool
	servers         map[string]*ServerEntry
}

type ConnectInput struct {
	Host         string `json:"host" jsonschema:"Hostname or IP address"`
	User         string `json:"user,omitempty" jsonschema:"SSH username (default root) or Windows username for WinRM"`
	Port         int    `json:"port,omitempty" jsonschema:"Port (SSH default 22, WinRM default 5985/5986)"`
	IdentityFile string `json:"identity_file,omitempty" jsonschema:"Path to SSH identity file"`
	Password     string `json:"password,omitempty" jsonschema:"SSH or WinRM password"`
	Passphrase   string `json:"passphrase,omitempty" jsonschema:"Passphrase for encrypted key"`
	Transport    string `json:"transport,omitempty" jsonschema:"Transport type: ssh (default), local, or winrm"`
	UseTLS       bool   `json:"use_tls,omitempty" jsonschema:"WinRM: use HTTPS (port 5986)"`
	Insecure     bool   `json:"insecure,omitempty" jsonschema:"WinRM: skip TLS certificate verification"`
	Command      string `json:"command,omitempty" jsonschema:"Local transport: shell command line spawned under a PTY (e.g. 'bash', 'zsh -l', 'ssh user@host -o ProxyJump=bastion'). The subprocess is held open for the lifetime of the connection."`
}

type ExecuteInput struct {
	Command string `json:"command" jsonschema:"Shell command or pipeline to execute"`
	Host    string `json:"host,omitempty" jsonschema:"Hostname when multiple connections exist"`
}

type DisconnectInput struct {
	Host string `json:"host,omitempty" jsonschema:"Hostname to disconnect; empty disconnects all"`
}

type ProvisionInput struct {
	Host string `json:"host,omitempty" jsonschema:"Hostname to provision. Required when connected to multiple servers."`
}

type SleepInput struct {
	Seconds float64 `json:"seconds" jsonschema:"Duration to sleep in seconds"`
}

type DownloadInput struct {
	RemotePath string `json:"remote_path" jsonschema:"Absolute path to file on remote server"`
	LocalDir   string `json:"local_dir,omitempty" jsonschema:"Local directory to save to (default: /tmp/shellguard-downloads/)"`
	Host       string `json:"host,omitempty" jsonschema:"Hostname when multiple connections exist"`
}

type DownloadResult struct {
	LocalPath string `json:"local_path"`
	SizeBytes int64  `json:"size_bytes"`
	Filename  string `json:"filename"`
}

type CoreOption func(*Core)

func WithDefaultTimeout(seconds int) CoreOption {
	return func(c *Core) { c.DefaultTimeout = seconds }
}

func WithMaxOutputBytes(bytes int) CoreOption {
	return func(c *Core) { c.MaxOutputBytes = bytes }
}

func WithMaxDownloadBytes(bytes int) CoreOption {
	return func(c *Core) { c.MaxDownloadBytes = bytes }
}

func WithDownloadDir(dir string) CoreOption {
	return func(c *Core) { c.DownloadDir = dir }
}

func WithMaxSleepSeconds(seconds int) CoreOption {
	return func(c *Core) { c.MaxSleepSeconds = seconds }
}

func WithDisabledTools(tools []string) CoreOption {
	return func(c *Core) {
		c.DisabledTools = make(map[string]bool, len(tools))
		for _, t := range tools {
			c.DisabledTools[t] = true
		}
	}
}

func NewCore(registry map[string]*manifest.Manifest, runner Executor, logger *slog.Logger, opts ...CoreOption) *Core {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	c := &Core{
		Registry:         registry,
		Runner:           runner,
		LocalRunner:      NewLocalExecutor(),
		logger:           logger,
		Parse:            parser.Parse,
		Validate:         validator.ValidatePipeline,
		Reconstruct:      ssh.ReconstructCommand,
		Truncate:         output.TruncateOutput,
		DefaultTimeout:   30,
		MaxOutputBytes:   output.DefaultMaxBytes,
		MaxDownloadBytes: maxDownloadBytes,
		DownloadDir:      defaultDownloadDir,
		MaxSleepSeconds:  15,
		probeState:       make(map[string]*ProbeResult),
		toolkitDeployed:  make(map[string]bool),
		servers:          make(map[string]*ServerEntry),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Close disconnects all SSH sessions and clears internal state.
// Internal state is always cleared even if the disconnect fails.
// It is safe to call multiple times.
func (c *Core) Close(ctx context.Context) error {
	err := c.Runner.Disconnect(ctx, "")
	_ = c.LocalRunner.Disconnect(ctx, "")
	if c.WinRMRunner != nil {
		_ = c.WinRMRunner.Disconnect(ctx, "")
	}
	c.clearHostState("")
	if err != nil {
		c.logger.InfoContext(ctx, "close", "outcome", "error", "error", err.Error())
		return err
	}
	c.logger.InfoContext(ctx, "close", "outcome", "success")
	return nil
}

// Logger returns the logger used by this Core.
func (c *Core) Logger() *slog.Logger {
	return c.logger
}

func (c *Core) Connect(ctx context.Context, in ConnectInput) (map[string]any, error) {
	if strings.TrimSpace(in.Host) == "" {
		return nil, errors.New("host is required")
	}

	start := time.Now()

	if strings.EqualFold(in.Transport, "local") {
		if strings.TrimSpace(in.Command) != "" {
			if err := c.LocalRunner.Connect(ctx, ssh.ConnectionParams{
				Host:    in.Host,
				Command: in.Command,
			}); err != nil {
				c.logger.InfoContext(ctx, "connect",
					"host", in.Host,
					"transport", "local",
					"outcome", "error",
					"error", err.Error(),
					"duration_ms", time.Since(start).Milliseconds(),
				)
				return nil, err
			}
		}
		c.setConnected(in.Host, TransportLocal, ShellBash, true)
		c.logger.InfoContext(ctx, "connect",
			"host", in.Host,
			"transport", "local",
			"outcome", "success",
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return map[string]any{"ok": true, "host": in.Host, "message": fmt.Sprintf("Connected to %s (local)", in.Host)}, nil
	}

	if strings.EqualFold(in.Transport, "winrm") {
		return c.connectWinRM(ctx, in, start)
	}

	params := ssh.ConnectionParams{
		Host:         in.Host,
		User:         in.User,
		Port:         in.Port,
		IdentityFile: in.IdentityFile,
		Password:     in.Password,
		Passphrase:   in.Passphrase,
	}
	if err := c.Runner.Connect(ctx, params); err != nil {
		c.logger.InfoContext(ctx, "connect",
			"host", in.Host,
			"outcome", "error",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, err
	}
	c.setConnected(in.Host, TransportSSH, ShellBash, true)
	c.setToolkitDeployed(in.Host, false)
	c.clearProbeState(in.Host)

	message := fmt.Sprintf("Connected to %s", in.Host)

	probeRes, err := c.Runner.ExecuteRaw(ctx, in.Host, toolkit.BuildProbeCommand(), 10*time.Second)
	if err == nil {
		missing, arch := toolkit.ParseProbeOutput(probeRes.Stdout)
		c.setProbeState(in.Host, &ProbeResult{Missing: missing, Arch: arch})
		if len(missing) > 0 {
			message += toolkit.FormatMissingToolsMessage(missing, arch)
		}
	}

	toolkitDirCheck, err := c.Runner.ExecuteRaw(ctx, in.Host, "test -d $HOME/.shellguard/bin && echo yes", 5*time.Second)
	if err == nil && strings.TrimSpace(toolkitDirCheck.Stdout) == "yes" {
		c.setToolkitDeployed(in.Host, true)
	}

	c.logger.InfoContext(ctx, "connect",
		"host", in.Host,
		"outcome", "success",
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return map[string]any{"ok": true, "host": in.Host, "message": message}, nil
}

func (c *Core) connectWinRM(ctx context.Context, in ConnectInput, start time.Time) (map[string]any, error) {
	if c.WinRMRunner == nil {
		return nil, errors.New("WinRM transport is not configured")
	}

	params := ssh.ConnectionParams{
		Host:     in.Host,
		User:     in.User,
		Port:     in.Port,
		Password: in.Password,
		UseTLS:   in.UseTLS,
		Insecure: in.Insecure,
	}

	if err := c.WinRMRunner.Connect(ctx, params); err != nil {
		c.logger.InfoContext(ctx, "connect",
			"host", in.Host,
			"transport", "winrm",
			"outcome", "error",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, err
	}

	c.setConnected(in.Host, TransportWinRM, ShellPowerShell, true)

	c.logger.InfoContext(ctx, "connect",
		"host", in.Host,
		"transport", "winrm",
		"shell", "powershell",
		"outcome", "success",
		"duration_ms", time.Since(start).Milliseconds(),
	)

	message := fmt.Sprintf("Connected to %s (winrm/powershell)", in.Host)
	return map[string]any{
		"ok":      true,
		"host":    in.Host,
		"shell":   "powershell",
		"message": message,
		"hint":    "Use PowerShell cmdlets (Get-Process, Get-Service, Get-WinEvent, etc.). Single quotes only, no $ or {} or ;. Use | to pipe between commands.",
	}, nil
}

func (c *Core) Execute(ctx context.Context, in ExecuteInput) (output.CommandResult, error) {
	if strings.TrimSpace(in.Command) == "" {
		return output.CommandResult{}, errors.New("command is required")
	}

	start := time.Now()
	hostForState := c.resolveHostForState(in.Host)
	shell := c.getShellType(hostForState)

	// Select parser based on shell type.
	parseFn := c.Parse
	if shell == ShellPowerShell && c.ParsePS != nil {
		parseFn = c.ParsePS
	}

	pipeline, err := parseFn(in.Command)
	if err != nil {
		c.logger.InfoContext(ctx, "execute",
			"command", in.Command,
			"host", in.Host,
			"outcome", "rejected",
			"stage", "parse",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return output.CommandResult{}, err
	}
	if err := c.Validate(pipeline, c.Registry); err != nil {
		c.logger.InfoContext(ctx, "execute",
			"command", in.Command,
			"host", in.Host,
			"outcome", "rejected",
			"stage", "validate",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return output.CommandResult{}, err
	}

	var reconstructed string
	if shell == ShellPowerShell && c.ReconstructPS != nil {
		psCmd := c.ReconstructPS(pipeline)
		reconstructed = winrmPkg.WrapForWinRM(psCmd)
	} else {
		isPSQL := pipelineContainsPSQL(pipeline)
		reconstructed = c.Reconstruct(pipeline, isPSQL, c.isToolkitDeployed(hostForState))
	}
	timeout := c.getPipelineTimeout(pipeline)

	execRes, err := c.resolveRunner(hostForState).Execute(ctx, in.Host, reconstructed, timeout)
	if err != nil {
		c.logger.InfoContext(ctx, "execute",
			"command", in.Command,
			"host", in.Host,
			"outcome", "error",
			"stage", "run",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return output.CommandResult{}, err
	}

	c.logger.InfoContext(ctx, "execute",
		"command", in.Command,
		"host", in.Host,
		"outcome", "success",
		"exit_code", execRes.ExitCode,
		"duration_ms", time.Since(start).Milliseconds(),
	)

	truncated := c.Truncate(execRes.Stdout, execRes.Stderr, execRes.ExitCode, execRes.RuntimeMs, c.MaxOutputBytes)
	truncated.Host = hostForState
	return truncated, nil
}

func (c *Core) Provision(ctx context.Context, in ProvisionInput) (map[string]any, error) {
	host, err := c.resolveProvisionHost(in.Host)
	if err != nil {
		return nil, err
	}

	start := time.Now()

	probe, ok := c.getProbeState(host)
	if !ok || len(probe.Missing) == 0 {
		c.logger.InfoContext(ctx, "provision",
			"host", host,
			"outcome", "success",
			"detail", "nothing_missing",
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return map[string]any{
			"ok":      true,
			"host":    host,
			"message": "All toolkit tools are already available. Nothing to deploy.",
		}, nil
	}

	if strings.TrimSpace(probe.Arch) == "" || probe.Arch == "unknown" {
		c.logger.InfoContext(ctx, "provision",
			"host", host,
			"outcome", "error",
			"error", "architecture unknown",
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, errors.New("cannot provision: architecture unknown")
	}

	sftpClient, err := c.Runner.SFTPSession(host)
	if err != nil {
		c.logger.InfoContext(ctx, "provision",
			"host", host,
			"outcome", "error",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, err
	}
	defer func() { _ = sftpClient.Close() }()

	message, err := toolkit.DeployTools(ctx, sftpClient, probe.Missing, probe.Arch)
	if err != nil {
		c.logger.InfoContext(ctx, "provision",
			"host", host,
			"outcome", "error",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, err
	}

	c.setToolkitDeployed(host, true)
	c.clearProbeState(host)

	c.logger.InfoContext(ctx, "provision",
		"host", host,
		"outcome", "success",
		"tools_deployed", probe.Missing,
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return map[string]any{
		"ok":      true,
		"host":    host,
		"message": message,
	}, nil
}

func (c *Core) Disconnect(ctx context.Context, in DisconnectInput) (map[string]any, error) {
	if err := c.resolveRunner(in.Host).Disconnect(ctx, in.Host); err != nil {
		c.logger.InfoContext(ctx, "disconnect",
			"host", in.Host,
			"outcome", "error",
			"error", err.Error(),
		)
		return nil, err
	}
	c.clearHostState(in.Host)

	c.logger.InfoContext(ctx, "disconnect",
		"host", in.Host,
		"outcome", "success",
	)

	return map[string]any{"ok": true}, nil
}

func (c *Core) DownloadFile(ctx context.Context, in DownloadInput) (DownloadResult, error) {
	if strings.TrimSpace(in.RemotePath) == "" {
		return DownloadResult{}, errors.New("remote_path is required")
	}

	host, err := c.resolveProvisionHost(in.Host)
	if err != nil {
		return DownloadResult{}, err
	}

	start := time.Now()

	sftpClient, err := c.Runner.SFTPSession(host)
	if err != nil {
		c.logger.InfoContext(ctx, "download",
			"remote_path", in.RemotePath,
			"host", host,
			"outcome", "error",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return DownloadResult{}, err
	}
	defer func() { _ = sftpClient.Close() }()

	info, err := sftpClient.Stat(in.RemotePath)
	if err != nil {
		c.logger.InfoContext(ctx, "download",
			"remote_path", in.RemotePath,
			"host", host,
			"outcome", "error",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return DownloadResult{}, fmt.Errorf("stat remote file %s: %w", in.RemotePath, err)
	}
	if info.IsDir() {
		return DownloadResult{}, fmt.Errorf("remote path is a directory: %s", in.RemotePath)
	}
	if info.Size() > int64(c.MaxDownloadBytes) {
		return DownloadResult{}, fmt.Errorf("file too large: %d bytes exceeds %d byte limit", info.Size(), c.MaxDownloadBytes)
	}

	localDir := strings.TrimSpace(in.LocalDir)
	if localDir == "" {
		localDir = c.DownloadDir
	}
	if err := os.MkdirAll(localDir, 0o755); err != nil {
		return DownloadResult{}, fmt.Errorf("create local directory %s: %w", localDir, err)
	}

	filename := filepath.Base(in.RemotePath)
	if filename == "." || filename == string(filepath.Separator) || filename == "" {
		return DownloadResult{}, fmt.Errorf("invalid remote filename: %s", in.RemotePath)
	}
	localPath, err := collisionSafePath(localDir, filename)
	if err != nil {
		return DownloadResult{}, err
	}

	src, err := sftpClient.Open(in.RemotePath)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("open remote file %s: %w", in.RemotePath, err)
	}
	defer func() { _ = src.Close() }()

	dst, err := os.Create(localPath)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("create local file %s: %w", localPath, err)
	}

	copied, copyErr := io.Copy(dst, src)
	closeErr := dst.Close()
	if copyErr != nil {
		_ = os.Remove(localPath)
		return DownloadResult{}, fmt.Errorf("copy remote file %s to %s: %w", in.RemotePath, localPath, copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(localPath)
		return DownloadResult{}, fmt.Errorf("close local file %s: %w", localPath, closeErr)
	}

	c.logger.InfoContext(ctx, "download",
		"remote_path", in.RemotePath,
		"host", host,
		"outcome", "success",
		"size_bytes", copied,
		"local_path", localPath,
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return DownloadResult{
		LocalPath: localPath,
		SizeBytes: copied,
		Filename:  filepath.Base(localPath),
	}, nil
}

func (c *Core) getPipelineTimeout(p *parser.Pipeline) time.Duration {
	maxSec := c.DefaultTimeout
	for _, seg := range p.Segments {
		m := c.Registry[seg.Command]
		if m != nil && m.Timeout > maxSec {
			maxSec = m.Timeout
		}
		if manifest.SubcommandCommands[seg.Command] && len(seg.Args) > 0 {
			key := seg.Command + "_" + seg.Args[0]
			if seg.Command == "aws" && len(seg.Args) >= 2 {
				key = seg.Command + "_" + seg.Args[0] + "_" + seg.Args[1]
			}
			if sm := c.Registry[key]; sm != nil && sm.Timeout > maxSec {
				maxSec = sm.Timeout
			}
		}
	}
	return time.Duration(maxSec) * time.Second
}

func pipelineContainsPSQL(p *parser.Pipeline) bool {
	for _, s := range p.Segments {
		if s.Command == "psql" {
			return true
		}
		if s.Command == "sudo" && len(s.Args) >= 3 && s.Args[0] == "-u" && s.Args[2] == "psql" {
			return true
		}
		if s.Command == "sudo" && len(s.Args) >= 1 && s.Args[0] == "psql" {
			return true
		}
	}
	return false
}

func (c *Core) resolveHostForState(host string) string {
	if host != "" {
		return host
	}
	hosts := c.ConnectedHostsSnapshot()
	if len(hosts) == 1 {
		return hosts[0]
	}
	return ""
}

func (c *Core) resolveProvisionHost(host string) (string, error) {
	if host != "" {
		if !c.isConnected(host) {
			return "", fmt.Errorf("not connected to host %q", host)
		}
		return host, nil
	}
	hosts := c.ConnectedHostsSnapshot()
	switch len(hosts) {
	case 0:
		return "", errors.New("not connected")
	case 1:
		return hosts[0], nil
	default:
		return "", errors.New("host is required when multiple connections are active")
	}
}

// ConnectedHostsSnapshot returns a sorted snapshot of currently connected hosts.
func (c *Core) ConnectedHostsSnapshot() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	hosts := make([]string, 0, len(c.servers))
	for host, entry := range c.servers {
		if entry.Connected {
			hosts = append(hosts, host)
		}
	}
	sort.Strings(hosts)
	return hosts
}

// ServersSnapshot returns a snapshot of all server entries.
func (c *Core) ServersSnapshot() StatusResult {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make(StatusResult, len(c.servers))
	for host, entry := range c.servers {
		result[host] = ServerStatus{
			Connected: entry.Connected,
			Transport: entry.Transport,
			Shell:     entry.Shell,
		}
	}
	return result
}

func (c *Core) isConnected(host string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.servers[host]
	return ok && entry.Connected
}

func (c *Core) setConnected(host string, transport TransportType, shell ShellType, connected bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if connected {
		c.servers[host] = &ServerEntry{Transport: transport, Shell: shell, Connected: true}
		return
	}
	delete(c.servers, host)
}

func (c *Core) getTransport(host string) TransportType {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if entry, ok := c.servers[host]; ok {
		return entry.Transport
	}
	return TransportSSH
}

func (c *Core) getShellType(host string) ShellType {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if entry, ok := c.servers[host]; ok {
		return entry.Shell
	}
	return ShellBash
}

func (c *Core) resolveRunner(host string) Executor {
	transport := c.getTransport(host)
	switch transport {
	case TransportLocal:
		return c.LocalRunner
	case TransportWinRM:
		if c.WinRMRunner != nil {
			return c.WinRMRunner
		}
		return c.Runner
	default:
		return c.Runner
	}
}

func (c *Core) setProbeState(host string, result *ProbeResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if result == nil {
		delete(c.probeState, host)
		return
	}
	cloned := &ProbeResult{
		Missing: append([]string(nil), result.Missing...),
		Arch:    result.Arch,
	}
	c.probeState[host] = cloned
}

func (c *Core) getProbeState(host string) (*ProbeResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result, ok := c.probeState[host]
	if !ok || result == nil {
		return nil, false
	}
	return &ProbeResult{
		Missing: append([]string(nil), result.Missing...),
		Arch:    result.Arch,
	}, true
}

func (c *Core) clearProbeState(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.probeState, host)
}

func (c *Core) setToolkitDeployed(host string, deployed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.toolkitDeployed[host] = deployed
}

func (c *Core) isToolkitDeployed(host string) bool {
	if host == "" {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.toolkitDeployed[host]
}

func (c *Core) clearHostState(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if host == "" {
		clear(c.servers)
		clear(c.probeState)
		clear(c.toolkitDeployed)
		return
	}
	delete(c.servers, host)
	delete(c.probeState, host)
	delete(c.toolkitDeployed, host)
}

func collisionSafePath(dir, filename string) (string, error) {
	base := strings.TrimSuffix(filename, filepath.Ext(filename))
	ext := filepath.Ext(filename)
	candidate := filepath.Join(dir, filename)

	if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
		return candidate, nil
	} else if err != nil {
		return "", fmt.Errorf("stat local path %s: %w", candidate, err)
	}

	for i := 1; i <= maxCollisionRetries; i++ {
		candidate = filepath.Join(dir, fmt.Sprintf("%s_%d%s", base, i, ext))
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate, nil
		} else if err != nil {
			return "", fmt.Errorf("stat local path %s: %w", candidate, err)
		}
	}

	return "", fmt.Errorf("filename collision: exhausted %d candidates for %q", maxCollisionRetries, filename)
}

func (c *Core) ValidateCommand(_ context.Context, in ValidateInput) (ValidateResult, error) {
	if strings.TrimSpace(in.Command) == "" {
		return ValidateResult{}, errors.New("command is required")
	}

	pipeline, err := c.Parse(in.Command)
	if err != nil {
		return ValidateResult{OK: false, Reason: err.Error()}, nil
	}

	if err := c.Validate(pipeline, c.Registry); err != nil {
		var ve *validator.ValidationError
		if errors.As(err, &ve) {
			return ValidateResult{OK: false, Reason: ve.Message}, nil
		}
		return ValidateResult{OK: false, Reason: err.Error()}, nil
	}

	return ValidateResult{OK: true}, nil
}

func (c *Core) Status(_ context.Context, _ StatusInput) (StatusResult, error) {
	return c.ServersSnapshot(), nil
}

func (c *Core) Sleep(ctx context.Context, in SleepInput) (map[string]any, error) {
	if in.Seconds <= 0 {
		return nil, errors.New("seconds must be greater than 0")
	}
	if in.Seconds > float64(c.MaxSleepSeconds) {
		return nil, fmt.Errorf("seconds must not exceed %d", c.MaxSleepSeconds)
	}
	d := time.Duration(in.Seconds * float64(time.Second))
	select {
	case <-time.After(d):
		return map[string]any{"ok": true, "slept_seconds": in.Seconds}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type ServerOptions struct {
	// Name is the MCP server implementation name. Default: "shellguard".
	Name string
	// Version is the MCP server implementation version. Default: "0.2.0".
	Version string
	// AutoConnect, when non-nil, causes an automatic SSH connection after
	// the MCP handshake completes (via InitializedHandler).
	AutoConnect *ConnectInput
}

func NewMCPServer(core *Core, opts ...ServerOptions) *mcp.Server {
	name := "shellguard"
	version := "0.2.0"
	if len(opts) > 0 {
		if opts[0].Name != "" {
			name = opts[0].Name
		}
		if opts[0].Version != "" {
			version = opts[0].Version
		}
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: name, Version: version}, &mcp.ServerOptions{Logger: core.Logger()})

	mcp.AddTool(srv, &mcp.Tool{Name: "connect", Description: "Connect to a remote server via SSH or WinRM. Set transport to 'winrm' for Windows servers (uses PowerShell). Default transport is 'ssh' (uses bash)."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in ConnectInput) (*mcp.CallToolResult, map[string]any, error) {
			out, err := core.Connect(ctx, in)
			return nil, out, err
		})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "execute",
		Description: fmt.Sprintf("Execute a shell command on the connected remote server. "+
			"Commands are validated against a security allowlist before execution. "+
			"Denied commands return the reason and often suggest alternatives. "+
			"SSH connections use bash: simple commands, pipes (|), and conditional chaining (&& ||). "+
			"WinRM connections use PowerShell cmdlets: Get-Process, Get-Service, Get-WinEvent, etc. "+
			"PowerShell rules: single quotes only, no $, {}, or ; (except inside @{}). Use | to pipe. "+
			"Output is truncated to %d bytes (head/tail preserved) for large results.", core.MaxOutputBytes),
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint: true,
		},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ExecuteInput) (*mcp.CallToolResult, output.CommandResult, error) {
		out, err := core.Execute(ctx, in)
		return nil, out, err
	})

	mcp.AddTool(srv, &mcp.Tool{Name: "disconnect", Description: "Disconnect from remote server(s)"},
		func(ctx context.Context, _ *mcp.CallToolRequest, in DisconnectInput) (*mcp.CallToolResult, map[string]any, error) {
			out, err := core.Disconnect(ctx, in)
			return nil, out, err
		})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "validate",
		Description: "Validate a shell command against the security policy without executing it.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ValidateInput) (*mcp.CallToolResult, ValidateResult, error) {
		out, err := core.ValidateCommand(ctx, in)
		return nil, out, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "status",
		Description: "Show connection status for all servers.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in StatusInput) (*mcp.CallToolResult, StatusResult, error) {
		out, err := core.Status(ctx, in)
		return nil, out, err
	})

	if !core.DisabledTools["sleep"] {
		mcp.AddTool(srv, &mcp.Tool{Name: "sleep", Description: fmt.Sprintf("Sleep locally for a specified duration (max %d seconds). Use to wait between checks, e.g. after observing an issue and before re-checking.", core.MaxSleepSeconds)},
			func(ctx context.Context, _ *mcp.CallToolRequest, in SleepInput) (*mcp.CallToolResult, map[string]any, error) {
				out, err := core.Sleep(ctx, in)
				return nil, out, err
			})
	}

	if !core.DisabledTools["provision"] {
		mcp.AddTool(srv, &mcp.Tool{
			Name:        "provision",
			Description: "Deploy missing diagnostic tools (rg, jq, yq) to ~/.shellguard/bin/ on the remote server. Uses SFTP over the existing SSH connection -- no outbound internet required on the remote. This is a WRITE operation: ask the operator for approval before calling this tool.",
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   false,
				IdempotentHint: true,
			},
		}, func(ctx context.Context, _ *mcp.CallToolRequest, in ProvisionInput) (*mcp.CallToolResult, map[string]any, error) {
			out, err := core.Provision(ctx, in)
			return nil, out, err
		})
	}

	if !core.DisabledTools["download_file"] {
		mcp.AddTool(srv, &mcp.Tool{
			Name: "download_file",
			Description: fmt.Sprintf("Download a file from the remote server to the local filesystem via SFTP. "+
				"Returns the local path so you can process the file with local tools. "+
				"Maximum file size: %d bytes. Files are saved to %s by default. "+
				"This is a WRITE operation on the local machine: ask the operator for approval before calling this tool.",
				core.MaxDownloadBytes, core.DownloadDir),
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint: false,
			},
		}, func(ctx context.Context, _ *mcp.CallToolRequest, in DownloadInput) (*mcp.CallToolResult, DownloadResult, error) {
			out, err := core.DownloadFile(ctx, in)
			return nil, out, err
		})
	}

	return srv
}

func RunStdio(ctx context.Context, core *Core, opts ...ServerOptions) error {
	server := NewMCPServer(core, opts...)
	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		return fmt.Errorf("run mcp stdio server: %w", err)
	}
	return nil
}

// NewHTTPHandler returns an http.Handler serving MCP over SSE.
func NewHTTPHandler(core *Core, opts ...ServerOptions) http.Handler {
	srv := NewMCPServer(core, opts...)
	return mcp.NewSSEHandler(func(_ *http.Request) *mcp.Server {
		return srv
	}, nil)
}
