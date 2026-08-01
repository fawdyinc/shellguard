package manifest

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func parseYAML(t *testing.T, src string) (*Manifest, error) {
	t.Helper()
	var data map[string]any
	if err := yaml.Unmarshal([]byte(src), &data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return parseManifest(data, "test.yaml")
}

func TestPositionalAllowlistParses(t *testing.T) {
	m, err := parseYAML(t, `
name: tool
positional_allowlist:
  index: 1
  values: ["A.read", "B.read"]
`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.PositionalAllowlist == nil {
		t.Fatal("positional_allowlist not parsed")
	}
	if m.PositionalAllowlist.Index != 1 {
		t.Errorf("index = %d, want 1", m.PositionalAllowlist.Index)
	}
	if !m.PositionalAllowlist.Allows("A.read") || m.PositionalAllowlist.Allows("A.write") {
		t.Error("Allows did not match the declared values")
	}
}

// Diagnostic command names are case-sensitive, so the match must be too --
// case-folding here would let GC.RUN through a list naming only GC.run.
func TestPositionalAllowlistIsCaseSensitive(t *testing.T) {
	m, err := parseYAML(t, `
name: tool
positional_allowlist:
  values: ["Thread.print"]
`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.PositionalAllowlist.Allows("thread.print") {
		t.Error("matching should be case-sensitive")
	}
}

// An empty values list would reject every invocation, which reads as a
// validator bug rather than a manifest bug. Fail at load time instead.
func TestPositionalAllowlistRejectsEmptyValues(t *testing.T) {
	_, err := parseYAML(t, `
name: tool
positional_allowlist:
  index: 1
  values: []
`)
	if err == nil {
		t.Fatal("expected an error for an empty values list")
	}
	if !strings.Contains(err.Error(), "must not be empty") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPositionalAllowlistRejectsNegativeIndex(t *testing.T) {
	_, err := parseYAML(t, `
name: tool
positional_allowlist:
  index: -1
  values: ["x"]
`)
	if err == nil {
		t.Fatal("expected an error for a negative index")
	}
}

func TestPositionalAllowlistRejectsNonMapping(t *testing.T) {
	_, err := parseYAML(t, `
name: tool
positional_allowlist: ["x"]
`)
	if err == nil {
		t.Fatal("expected an error when positional_allowlist is not a mapping")
	}
}

func TestPositionalAllowlistAbsentByDefault(t *testing.T) {
	m, err := parseYAML(t, "name: tool\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.PositionalAllowlist != nil {
		t.Error("positional_allowlist should be nil when absent")
	}
}
