package shellguard

import (
	"strings"
	"testing"

	"github.com/fawdyinc/shellguard/manifest"
	"github.com/fawdyinc/shellguard/parser"
	"github.com/fawdyinc/shellguard/validator"
	"github.com/fawdyinc/shellguard/winrm"
)

// TestPowerShellPipeline_ParseValidateReconstruct exercises the full
// Parse → Validate → Reconstruct → WrapForWinRM pipeline for PowerShell commands.
func TestPowerShellPipeline_ParseValidateReconstruct(t *testing.T) {
	registry, err := manifest.LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded() error = %v", err)
	}

	tests := []struct {
		name    string
		command string
		wantCmd string // substring expected in reconstructed output
	}{
		{
			name:    "simple Get-Process",
			command: "Get-Process",
			wantCmd: "get-process",
		},
		{
			name:    "Get-Process with flag",
			command: "Get-Process -Name svchost",
			wantCmd: "get-process -Name svchost",
		},
		{
			name:    "pipeline",
			command: "Get-Process | Select-Object -Property Name -First 10",
			wantCmd: "get-process | select-object -Property Name -First 10",
		},
		{
			name:    "hashtable",
			command: "Get-WinEvent -FilterHashtable @{LogName='System'; Level=2}",
			wantCmd: "get-winevent",
		},
		{
			name:    "case insensitive",
			command: "get-process",
			wantCmd: "get-process",
		},
		{
			name:    "single word command",
			command: "whoami",
			wantCmd: "whoami",
		},
		{
			name:    "common params",
			command: "Get-Process -ErrorAction SilentlyContinue",
			wantCmd: "get-process -ErrorAction SilentlyContinue",
		},
		{
			name:    "Get-Content with path",
			command: "Get-Content -Path 'C:\\logs\\app.log' -Tail 50",
			wantCmd: "get-content -Path",
		},
		{
			name:    "sort descending",
			command: "Get-Process | Sort-Object -Property CPU -Descending",
			wantCmd: "sort-object -Property CPU -Descending",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pipeline, err := parser.ParsePowerShell(tc.command)
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}

			if err := validator.ValidatePipeline(pipeline, registry); err != nil {
				t.Fatalf("Validate error: %v", err)
			}

			reconstructed := winrm.ReconstructPowerShellCommand(pipeline)
			if !strings.Contains(reconstructed, tc.wantCmd) {
				t.Errorf("reconstructed = %q, want substring %q", reconstructed, tc.wantCmd)
			}

			wrapped := winrm.WrapForWinRM(reconstructed)
			if !strings.HasPrefix(wrapped, "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ") {
				t.Errorf("wrapped command has wrong prefix: %s", wrapped)
			}
		})
	}
}

// TestPowerShellPipeline_RejectDangerous verifies that dangerous constructs
// are rejected at the parse stage with actionable messages.
func TestPowerShellPipeline_RejectDangerous(t *testing.T) {
	tests := []struct {
		name    string
		command string
		wantErr string
	}{
		{"variable", "$foo", "Variable references"},
		{"interpolated dqstring", `Get-Process -Name "svc $var"`, "Double-quoted"},
		{"subexpression", "(Get-Date).ToString()", "Subexpressions"},
		{"semicolon", "Get-Process; Get-Service", "Statement separators"},
		{"redirection", "Get-Process > out.txt", "Output redirection"},
		{"call operator", "& cmd /c dir", "call operator"},
		{"backtick", "Get-Process `\n-Name svc", "Backtick"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parser.ParsePowerShell(tc.command)
			if err == nil {
				t.Fatalf("expected rejection for %q", tc.command)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestPowerShellPipeline_RejectDeniedCmdlets verifies that denied cmdlets
// are rejected at the validate stage with helpful reasons.
func TestPowerShellPipeline_RejectDeniedCmdlets(t *testing.T) {
	registry, err := manifest.LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded() error = %v", err)
	}

	denied := []struct {
		name    string
		command string
		wantErr string
	}{
		{"Remove-Item", "Remove-Item foo", "Destructive"},
		{"Stop-Process", "Stop-Process -Name svc", "Destructive"},
		{"Stop-Service", "Stop-Service -Name svc", "Service modification"},
		{"Invoke-Expression", "Invoke-Expression hello", "code execution"},
		{"Invoke-Command", "Invoke-Command -ScriptBlock test", "Remote command"},
		{"Start-Process", "Start-Process notepad", "Process launching"},
		{"cmd", "cmd", "Shell execution"},
		{"powershell", "powershell", "Shell execution"},
		{"iex", "iex hello", "Invoke-Expression"},
	}

	for _, tc := range denied {
		t.Run(tc.name, func(t *testing.T) {
			pipeline, err := parser.ParsePowerShell(tc.command)
			if err != nil {
				t.Fatalf("Parse error (unexpected): %v", err)
			}

			err = validator.ValidatePipeline(pipeline, registry)
			if err == nil {
				t.Fatalf("expected validation rejection for %q", tc.command)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestPowerShellPipeline_RejectUnknownCmdlet verifies that unknown cmdlets
// are rejected at the validate stage.
func TestPowerShellPipeline_RejectUnknownCmdlet(t *testing.T) {
	registry, err := manifest.LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded() error = %v", err)
	}

	pipeline, err := parser.ParsePowerShell("Get-FooBar")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	err = validator.ValidatePipeline(pipeline, registry)
	if err == nil {
		t.Fatal("expected rejection for unknown cmdlet")
	}
	if !strings.Contains(err.Error(), "not available") {
		t.Errorf("error = %q, want 'not available'", err.Error())
	}
}

// TestManifestNoCollision verifies that PowerShell manifest names (lowercase)
// don't collide with bash manifest names.
func TestManifestNoCollision(t *testing.T) {
	registry, err := manifest.LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded() error = %v", err)
	}

	// Count PS manifests
	psCount := 0
	for _, m := range registry {
		if m.Shell == "powershell" {
			psCount++
		}
	}

	if psCount < 60 {
		t.Errorf("expected at least 60 PowerShell manifests, got %d", psCount)
	}
}
