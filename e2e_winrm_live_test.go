package shellguard_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fawdyinc/shellguard/manifest"
	"github.com/fawdyinc/shellguard/parser"
	"github.com/fawdyinc/shellguard/ssh"
	"github.com/fawdyinc/shellguard/validator"
	"github.com/fawdyinc/shellguard/winrm"
)

// Live end-to-end smoke test against a real Windows host over WinRM.
//
// Every other test in this repo stops at string reconstruction. That gap is
// how the curl→Invoke-WebRequest alias bug shipped: the validator accepted
// `curl -k`, and the first process to notice that PowerShell resolves `curl`
// to a denied cmdlet was a customer demo. This suite runs the full
// parse → validate → reconstruct → WrapForWinRM → execute pipeline and
// asserts on real exit codes and output.
//
// Gated on environment; skips when unset so CI is unaffected:
//
//	SHELLGUARD_E2E_WINRM_HOST=192.168.1.50 \
//	SHELLGUARD_E2E_WINRM_USER=fawdytest \
//	SHELLGUARD_E2E_WINRM_PASSWORD=... \
//	go test -run TestLiveWinRM -v .
//
// Optional:
//
//	SHELLGUARD_E2E_HTTP_URL   HTTPS URL reachable from the Windows host
//	                          (default https://example.com)
//	SHELLGUARD_E2E_DSLS=1     also run DSCheckLS.exe -l (3DEXPERIENCE hosts)
func TestLiveWinRM(t *testing.T) {
	host := os.Getenv("SHELLGUARD_E2E_WINRM_HOST")
	if host == "" {
		t.Skip("SHELLGUARD_E2E_WINRM_HOST not set; skipping live WinRM e2e")
	}
	password := os.Getenv("SHELLGUARD_E2E_WINRM_PASSWORD")
	if password == "" {
		t.Fatal("SHELLGUARD_E2E_WINRM_HOST is set but SHELLGUARD_E2E_WINRM_PASSWORD is not")
	}

	registry, err := manifest.LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	scoped := validator.ScopeRegistry(registry, "powershell")

	mgr := winrm.NewWinRMManager(&winrm.WinRMDialer{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	err = mgr.Connect(ctx, ssh.ConnectionParams{
		Host:     host,
		User:     os.Getenv("SHELLGUARD_E2E_WINRM_USER"),
		Password: password,
	})
	if err != nil {
		t.Fatalf("connect to %s: %v", host, err)
	}
	defer func() { _ = mgr.Disconnect(ctx, host) }()

	// run pushes one command through the exact pipeline server.Core.Execute
	// uses for a WinRM host, then executes it for real.
	run := func(t *testing.T, command string) ssh.ExecResult {
		t.Helper()
		pipeline, err := parser.ParsePowerShell(command)
		if err != nil {
			t.Fatalf("parse rejected %q: %v", command, err)
		}
		if err := validator.ValidatePipeline(pipeline, scoped); err != nil {
			t.Fatalf("validator rejected %q: %v", command, err)
		}
		psCmd := winrm.ReconstructPowerShellCommand(pipeline)
		t.Logf("reconstructed: %s", psCmd)
		result, err := mgr.Execute(ctx, host, winrm.WrapForWinRM(psCmd), 60*time.Second)
		if err != nil {
			t.Fatalf("execute %q: %v", psCmd, err)
		}
		t.Logf("exit=%d runtime=%dms stdout[0:120]=%q stderr[0:200]=%q",
			result.ExitCode, result.RuntimeMs, firstN(result.Stdout, 120), firstN(result.Stderr, 200))
		return result
	}

	mustSucceed := func(t *testing.T, command string) ssh.ExecResult {
		t.Helper()
		result := run(t, command)
		if result.ExitCode != 0 {
			t.Fatalf("%q exited %d\nstderr: %s", command, result.ExitCode, result.Stderr)
		}
		if strings.TrimSpace(result.Stderr) != "" {
			t.Fatalf("%q wrote to stderr despite exit 0:\n%s", command, result.Stderr)
		}
		return result
	}

	t.Run("whoami", func(t *testing.T) {
		result := mustSucceed(t, "whoami")
		if strings.TrimSpace(result.Stdout) == "" {
			t.Fatal("whoami produced no output")
		}
	})

	t.Run("cmdlet_pipeline", func(t *testing.T) {
		result := mustSucceed(t, "Get-Service | Select-Object -Property Name -First 5")
		if !strings.Contains(result.Stdout, "Name") {
			t.Fatalf("expected service table, got: %s", firstN(result.Stdout, 200))
		}
	})

	t.Run("calculated_property", func(t *testing.T) {
		// The safe-expression grammar from PR #111 — keep it exercised live.
		// Exit code alone is not enough: the comma-list quoting bug found in
		// the 2026-08-20 windows-dev audit produced exit 0 with one
		// literal-named empty column. Require the MB header, numeric data,
		// and no hashtable text leaking into the output as a property name.
		result := mustSucceed(t, "Get-Process | Select-Object -First 3 -Property Name, @{N='MB';E={[math]::Round($_.WorkingSet64/1MB,1)}}")
		if strings.Contains(result.Stdout, "@{") {
			t.Fatalf("property list reached PowerShell as a single string, not an array: %s",
				firstN(result.Stdout, 300))
		}
		if !strings.Contains(result.Stdout, "MB") || !strings.ContainsAny(result.Stdout, "0123456789") {
			t.Fatalf("calculated property produced no data: %s", firstN(result.Stdout, 300))
		}
	})

	t.Run("tcp_port_check", func(t *testing.T) {
		// The TCP-level liveness probe the agent should reach for first.
		result := mustSucceed(t, fmt.Sprintf("Test-NetConnection %s -Port 5985", host))
		if !strings.Contains(result.Stdout, "TcpTestSucceeded") {
			t.Fatalf("unexpected Test-NetConnection output: %s", firstN(result.Stdout, 300))
		}
	})

	t.Run("http_get_curl", func(t *testing.T) {
		// The HTTP-level liveness probe. This is the case that failed at the
		// customer: `curl` validates, but inside powershell.exe it resolves to
		// the Invoke-WebRequest alias, which rejects curl's flags.
		url := os.Getenv("SHELLGUARD_E2E_HTTP_URL")
		if url == "" {
			url = "https://example.com"
		}
		result := run(t, fmt.Sprintf("curl -sS -k -m 10 -I '%s'", url))
		if strings.Contains(result.Stderr, "Invoke-WebRequest") ||
			strings.Contains(result.Stderr, "parameter") {
			t.Fatalf("curl resolved to the Invoke-WebRequest alias instead of curl.exe — "+
				"the validated command is not the command that ran.\nstderr: %s", result.Stderr)
		}
		if result.ExitCode != 0 {
			t.Fatalf("curl exited %d\nstderr: %s", result.ExitCode, result.Stderr)
		}
		if !strings.Contains(result.Stdout, "HTTP/") {
			t.Fatalf("expected HTTP status line, got: %s", firstN(result.Stdout, 200))
		}
	})

	t.Run("dsls_license_check", func(t *testing.T) {
		if os.Getenv("SHELLGUARD_E2E_DSLS") == "" {
			t.Skip("SHELLGUARD_E2E_DSLS not set; host is not a 3DEXPERIENCE server")
		}
		result := run(t, "DSCheckLS.exe -l")
		if strings.Contains(result.Stderr, "is not recognized") {
			t.Fatalf("DSCheckLS.exe validated but was not found at runtime — "+
				"not on PATH and full paths are rejected by design.\nstderr: %s", result.Stderr)
		}
		if result.ExitCode != 0 {
			t.Fatalf("DSCheckLS.exe -l exited %d\nstderr: %s", result.ExitCode, result.Stderr)
		}
	})
}

func firstN(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
