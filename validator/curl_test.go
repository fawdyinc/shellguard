package validator

import (
	"testing"
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
