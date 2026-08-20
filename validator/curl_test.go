package validator

import (
	"testing"

	"github.com/fawdyinc/shellguard/parser"
)

func TestCurlAllowsVerboseFlag(t *testing.T) {
	if err := validateOne(t, "curl", "-v", "http://example.com"); err != nil {
		t.Fatalf("curl -v should be allowed: %v", err)
	}
}

func TestCurlAllowsVerboseFlagCombined(t *testing.T) {
	if err := validateOne(t, "curl", "-vL", "http://example.com"); err != nil {
		t.Fatalf("curl -vL should be allowed: %v", err)
	}
}

// curl.exe is the explicit Windows spelling admitted on powershell scope
// (manifest/manifests/powershell/curl.exe.yaml); policy must mirror curl.
func TestCurlExePowerShellScope(t *testing.T) {
	registry := testRegistry(t)
	scoped := ScopeRegistry(registry, "powershell")

	accept := []string{
		"curl.exe -I -k -m 10 'https://example.com'",
		"curl.exe -sS -k -m 10 -w '%{http_code}' 'https://example.com'",
	}
	for _, cmd := range accept {
		p, err := parser.ParsePowerShell(cmd)
		if err != nil {
			t.Fatalf("parse %q: %v", cmd, err)
		}
		if err := ValidatePipeline(p, scoped); err != nil {
			t.Errorf("expected accept for %q, got: %v", cmd, err)
		}
	}

	reject := []string{
		"curl.exe -X POST 'https://example.com'",
		"curl.exe -o C:\\out.bin 'https://example.com'",
		"curl.exe -H 'Authorization: Bearer x' 'https://example.com'",
	}
	for _, cmd := range reject {
		p, err := parser.ParsePowerShell(cmd)
		if err != nil {
			continue // parse-level rejection is fine too
		}
		if err := ValidatePipeline(p, scoped); err == nil {
			t.Errorf("expected reject for %q", cmd)
		}
	}
}
