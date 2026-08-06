package validator

import (
	"strings"
	"testing"

	"github.com/fawdyinc/shellguard/parser"
)

// These commands come from a recorded 3DEXPERIENCE/SQL Server incident session
// (2026-08-05). Each was needed during diagnosis and rejected by the validator,
// costing turns or degrading the investigation.

func validatePS(t *testing.T, command string) error {
	t.Helper()
	p, err := parser.ParsePowerShell(command)
	if err != nil {
		t.Fatalf("parse %q: %v", command, err)
	}
	return ValidatePipeline(p, testRegistry(t))
}

// Without -Wrap, long Message fields truncate mid-sentence in table view,
// forcing a fallback to the far more verbose Format-List.
func TestFormatTableWrap(t *testing.T) {
	if err := validatePS(t, "Get-Process | Format-Table Name, CPU -AutoSize -Wrap"); err != nil {
		t.Errorf("Format-Table -Wrap should be allowed: %v", err)
	}
}

// -Filter takes a single Win32 glob; -Include is the only way to search for
// several file patterns (crash dumps, heap dumps, javacores) in one pass.
func TestGetChildItemInclude(t *testing.T) {
	if err := validatePS(t, `Get-ChildItem -Path 'C:\logs' -Recurse -Include 'hs_err_pid*.log','*.hprof'`); err != nil {
		t.Errorf("Get-ChildItem -Include should be allowed: %v", err)
	}
}

// -Context is grep -B/-A: log lines around a match, not just the match.
func TestSelectStringContext(t *testing.T) {
	if err := validatePS(t, `Select-String -Path 'C:\logs\app.log' -Pattern 'OutOfMemoryError' -Context 2,5`); err != nil {
		t.Errorf("Select-String -Context should be allowed: %v", err)
	}
}

// Bare `net accounts` is the only reader for lockout/password policy; the
// Get-* cmdlets the net denial points to cannot show it.
func TestNetAccountsAllowed(t *testing.T) {
	if err := validatePS(t, "net accounts"); err != nil {
		t.Errorf("net accounts should be allowed: %v", err)
	}
}

// net accounts with any argument is a write - /forcelogoff:30 and friends set
// the policy they otherwise display.
func TestNetAccountsRejectsArguments(t *testing.T) {
	if err := validateOne(t, "net", "accounts", "/forcelogoff:30"); err == nil {
		t.Error("net accounts with arguments must be rejected")
	}
}

func TestNetOtherSubcommandsStayDenied(t *testing.T) {
	for _, args := range [][]string{
		{"user"},
		{"user", "eve", "/add"},
		{"localgroup", "administrators"},
		{"share"},
	} {
		if err := validateOne(t, "net", args...); err == nil {
			t.Errorf("net %s must stay denied", strings.Join(args, " "))
		}
	}
}

func TestBareNetStaysDenied(t *testing.T) {
	if err := validateOne(t, "net"); err == nil {
		t.Error("bare net must stay denied")
	}
}
