package validator

import (
	"strings"
	"testing"

	"github.com/fawdyinc/shellguard/parser"
)

// validatePS parses a PowerShell command string and validates the resulting
// pipeline. End-to-end sanity for the HTTP probe policy lives here because the
// restricted-allow pattern for Invoke-WebRequest / Invoke-RestMethod relies on
// both the parser lowercasing cmdlet names and the manifest denying
// write-capable flags with reasons.
func validatePS(t *testing.T, command string) error {
	t.Helper()
	p, err := parser.ParsePowerShell(command)
	if err != nil {
		return err
	}
	return ValidatePipeline(p, testRegistry(t))
}

func TestInvokeWebRequestHealthcheckAllowed(t *testing.T) {
	cases := []string{
		"Invoke-WebRequest -Uri 'http://localhost:8080/health' -UseBasicParsing -TimeoutSec 10",
		"Invoke-WebRequest -Uri 'https://localhost:443/3dspace/' -Method Head -UseBasicParsing",
		"Invoke-RestMethod -Uri 'http://localhost:8080/api/v1/status' -TimeoutSec 5",
		"Invoke-RestMethod -Uri 'https://example.com/api' -Method GET -MaximumRedirection 3",
	}
	for _, c := range cases {
		if err := validatePS(t, c); err != nil {
			t.Errorf("expected allow for %q: %v", c, err)
		}
	}
}

func TestInvokeWebRequestWriteFlagsDenied(t *testing.T) {
	// Each case must reject. The reason string is user-visible, so we spot-check
	// that a relevant substring appears.
	cases := []struct {
		cmd       string
		mustMatch string
	}{
		{`Invoke-WebRequest -Uri 'http://x/' -Body 'foo'`, "body"},
		{`Invoke-WebRequest -Uri 'http://x/' -OutFile 'C:\out.txt'`, "disk"},
		{`Invoke-WebRequest -Uri 'http://x/' -InFile 'C:\up.bin'`, "upload"},
		{`Invoke-WebRequest -Uri 'http://x/' -Credential 'user'`, "credential"},
		{`Invoke-WebRequest -Uri 'http://x/' -SkipCertificateCheck`, "tls"},
		{`Invoke-WebRequest -Uri 'http://x/' -Proxy 'http://evil/'`, "proxy"},
		{`Invoke-WebRequest -Uri 'http://x/' -Headers @{Authorization='Bearer foo'}`, "header"},
		{`Invoke-WebRequest -Uri 'http://x/' -CustomMethod PUT`, "GET"},
		{`Invoke-RestMethod -Uri 'http://x/' -Body '{}'`, "body"},
		// Note: -WebSession / -SessionVariable take a $variable value, which the
		// parser already rejects at the expression level. The manifest deny is
		// belt-and-suspenders coverage verified by TestPowerShellDiagnosticManifests.
	}
	for _, c := range cases {
		err := validatePS(t, c.cmd)
		if err == nil {
			t.Errorf("BYPASS: expected rejection for %q", c.cmd)
			continue
		}
		if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(c.mustMatch)) {
			t.Errorf("rejection reason for %q should mention %q, got: %v", c.cmd, c.mustMatch, err)
		}
	}
}

func TestInvokeWebRequestMethodRestriction(t *testing.T) {
	// -Method GET/HEAD is allowed; PUT/POST/DELETE/PATCH must reject.
	allow := []string{
		"Invoke-WebRequest -Uri 'http://x/' -Method GET",
		"Invoke-WebRequest -Uri 'http://x/' -Method HEAD",
		"Invoke-RestMethod -Uri 'http://x/' -Method GET",
	}
	for _, c := range allow {
		if err := validatePS(t, c); err != nil {
			t.Errorf("expected allow for %q: %v", c, err)
		}
	}
	deny := []string{
		"Invoke-WebRequest -Uri 'http://x/' -Method POST",
		"Invoke-WebRequest -Uri 'http://x/' -Method PUT",
		"Invoke-WebRequest -Uri 'http://x/' -Method DELETE",
		"Invoke-WebRequest -Uri 'http://x/' -Method PATCH",
		"Invoke-RestMethod -Uri 'http://x/' -Method POST",
	}
	for _, c := range deny {
		if err := validatePS(t, c); err == nil {
			t.Errorf("BYPASS: expected rejection for %q", c)
		}
	}
}
