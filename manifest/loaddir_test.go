package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDir_ValidManifests(t *testing.T) {
	dir := t.TempDir()
	content := `name: mytool
description: A test tool
category: testing
timeout: 45
flags:
  - flag: "-v"
    description: verbose output
    takes_value: false
allows_path_args: true
`
	if err := os.WriteFile(filepath.Join(dir, "mytool.yaml"), []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	registry, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir() error = %v", err)
	}

	if got, want := len(registry), 1; got != want {
		t.Fatalf("len(registry) = %d, want %d", got, want)
	}

	m, ok := registry["mytool"]
	if !ok {
		t.Fatal("registry missing key \"mytool\"")
	}
	if got, want := m.Name, "mytool"; got != want {
		t.Fatalf("Name = %q, want %q", got, want)
	}
	if got, want := m.Description, "A test tool"; got != want {
		t.Fatalf("Description = %q, want %q", got, want)
	}
	if got, want := m.Category, "testing"; got != want {
		t.Fatalf("Category = %q, want %q", got, want)
	}
	if got, want := m.Timeout, 45; got != want {
		t.Fatalf("Timeout = %d, want %d", got, want)
	}

	f := m.GetFlag("-v")
	if f == nil {
		t.Fatal("GetFlag(\"-v\") = nil")
		return
	}
	if got, want := f.Description, "verbose output"; got != want {
		t.Fatalf("flag Description = %q, want %q", got, want)
	}
}

func TestLoadDir_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	registry, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir() error = %v", err)
	}
	if got, want := len(registry), 0; got != want {
		t.Fatalf("len(registry) = %d, want %d", got, want)
	}
}

func TestLoadDir_SkipsNonYAML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not yaml"), 0644); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	registry, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir() error = %v", err)
	}
	if got, want := len(registry), 0; got != want {
		t.Fatalf("len(registry) = %d, want %d", got, want)
	}
}

func TestLoadDir_SkipsUnderscorePrefix(t *testing.T) {
	dir := t.TempDir()
	content := `name: schema
description: should be skipped
`
	if err := os.WriteFile(filepath.Join(dir, "_schema.yaml"), []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	registry, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir() error = %v", err)
	}
	if got, want := len(registry), 0; got != want {
		t.Fatalf("len(registry) = %d, want %d", got, want)
	}
}

func TestLoadDir_Subdirectories(t *testing.T) {
	dir := t.TempDir()

	// Top-level manifest.
	topContent := `name: mytool
description: A top-level tool
category: testing
`
	if err := os.WriteFile(filepath.Join(dir, "mytool.yaml"), []byte(topContent), 0644); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	// Create denied/ subdirectory with a manifest.
	deniedDir := filepath.Join(dir, "denied")
	if err := os.MkdirAll(deniedDir, 0755); err != nil {
		t.Fatalf("MkdirAll error = %v", err)
	}
	deniedContent := `name: dangerous
description: A denied tool
deny: true
reason: too dangerous
`
	if err := os.WriteFile(filepath.Join(deniedDir, "dangerous.yaml"), []byte(deniedContent), 0644); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	registry, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir() error = %v", err)
	}

	if got, want := len(registry), 2; got != want {
		t.Fatalf("len(registry) = %d, want %d", got, want)
	}

	if _, ok := registry["mytool"]; !ok {
		t.Fatal("registry missing key \"mytool\"")
	}

	m, ok := registry["dangerous"]
	if !ok {
		t.Fatal("registry missing key \"dangerous\" from subdirectory")
	}
	if !m.Deny {
		t.Fatal("dangerous.Deny = false, want true")
	}
	if got, want := m.Reason, "too dangerous"; got != want {
		t.Fatalf("dangerous.Reason = %q, want %q", got, want)
	}
}

func TestLoadDir_NonexistentDir(t *testing.T) {
	_, err := LoadDir("/nonexistent/dir/that/does/not/exist")
	if err == nil {
		t.Fatal("LoadDir() should return error for nonexistent dir")
	}
}

func TestLoadDir_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(":::invalid:::yaml[[["), 0644); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	_, err := LoadDir(dir)
	if err == nil {
		t.Fatal("LoadDir() should return error for invalid YAML")
	}
}

func TestMerge(t *testing.T) {
	base := map[string]*Manifest{
		"ls":  {Name: "ls", Timeout: 30},
		"cat": {Name: "cat", Timeout: 30},
	}
	overlay := map[string]*Manifest{
		"ls":          {Name: "ls", Timeout: 60},
		"custom_tool": {Name: "custom_tool", Timeout: 10},
	}

	merged := Merge(base, overlay)

	if got, want := len(merged), 3; got != want {
		t.Fatalf("len(merged) = %d, want %d", got, want)
	}

	if got, want := merged["ls"].Timeout, 60; got != want {
		t.Fatalf("merged[\"ls\"].Timeout = %d, want %d", got, want)
	}
	if got, want := merged["cat"].Timeout, 30; got != want {
		t.Fatalf("merged[\"cat\"].Timeout = %d, want %d", got, want)
	}
	if _, ok := merged["custom_tool"]; !ok {
		t.Fatal("merged missing key \"custom_tool\"")
	}
}

func TestMerge_UserCanDenyBuiltin(t *testing.T) {
	base := map[string]*Manifest{
		"ls": {Name: "ls", Deny: false, Timeout: 30},
	}
	overlay := map[string]*Manifest{
		"ls": {Name: "ls", Deny: true, Reason: "not allowed"},
	}

	merged := Merge(base, overlay)

	if !merged["ls"].Deny {
		t.Fatal("merged[\"ls\"].Deny = false, want true")
	}
	if got, want := merged["ls"].Reason, "not allowed"; got != want {
		t.Fatalf("merged[\"ls\"].Reason = %q, want %q", got, want)
	}
}

func TestMerge_DoesNotMutateInputs(t *testing.T) {
	base := map[string]*Manifest{
		"ls":  {Name: "ls", Timeout: 30},
		"cat": {Name: "cat", Timeout: 30},
	}
	overlay := map[string]*Manifest{
		"ls":          {Name: "ls", Timeout: 60},
		"custom_tool": {Name: "custom_tool", Timeout: 10},
	}

	_ = Merge(base, overlay)

	// base should be unchanged
	if got, want := len(base), 2; got != want {
		t.Fatalf("len(base) = %d, want %d after Merge", got, want)
	}
	if _, ok := base["custom_tool"]; ok {
		t.Fatal("base should not contain \"custom_tool\" after Merge")
	}
	if got, want := base["ls"].Timeout, 30; got != want {
		t.Fatalf("base[\"ls\"].Timeout = %d, want %d after Merge", got, want)
	}

	// overlay should be unchanged
	if got, want := len(overlay), 2; got != want {
		t.Fatalf("len(overlay) = %d, want %d after Merge", got, want)
	}
}

func TestRequiresOneOfParsed(t *testing.T) {
	dir := t.TempDir()
	content := `name: mytool
flags:
  - flag: "-l"
  - flag: "-r"
    takes_value: true
requires_one_of: ["-l", "-r"]
`
	if err := os.WriteFile(filepath.Join(dir, "mytool.yaml"), []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	registry, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir() error = %v", err)
	}
	m := registry["mytool"]
	if m == nil {
		t.Fatal("registry missing key \"mytool\"")
	}
	if got, want := len(m.RequiresOneOf), 2; got != want {
		t.Fatalf("len(RequiresOneOf) = %d, want %d", got, want)
	}
	if got, want := m.RequiresOneOf[0], "-l"; got != want {
		t.Errorf("RequiresOneOf[0] = %q, want %q", got, want)
	}
}

func TestRequiresOneOfAbsentIsNil(t *testing.T) {
	dir := t.TempDir()
	content := `name: plain
flags:
  - flag: "-l"
`
	if err := os.WriteFile(filepath.Join(dir, "plain.yaml"), []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
	registry, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir() error = %v", err)
	}
	if got := registry["plain"].RequiresOneOf; got != nil {
		t.Errorf("RequiresOneOf = %v, want nil", got)
	}
}

// A typo in requires_one_of would make the tool permanently unusable in a way
// indistinguishable from a validator bug. Fail the build instead.
func TestRequiresOneOfRejectsUndeclaredFlag(t *testing.T) {
	dir := t.TempDir()
	content := `name: typo
flags:
  - flag: "-l"
requires_one_of: ["-1"]
`
	if err := os.WriteFile(filepath.Join(dir, "typo.yaml"), []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
	_, err := LoadDir(dir)
	if err == nil {
		t.Fatal("LoadDir() error = nil, want error for undeclared requires_one_of entry")
	}
	if !strings.Contains(err.Error(), "requires_one_of") {
		t.Errorf("error should name requires_one_of, got: %v", err)
	}
}

// A requires_one_of entry that is itself deny: true makes the tool
// permanently unusable: every invocation is rejected for missing the flag,
// and the one flag that would satisfy it is denied. That is the same
// "unusable in a way indistinguishable from a validator bug" failure the
// undeclared-entry check above exists to prevent. Fail the build instead.
func TestRequiresOneOfRejectsDeniedFlag(t *testing.T) {
	dir := t.TempDir()
	content := `name: denied
flags:
  - flag: "-t"
    deny: true
    reason: "consumes a license"
requires_one_of: ["-t"]
`
	if err := os.WriteFile(filepath.Join(dir, "denied.yaml"), []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
	_, err := LoadDir(dir)
	if err == nil {
		t.Fatal("LoadDir() error = nil, want error for denied requires_one_of entry")
	}
	if !strings.Contains(err.Error(), "requires_one_of") || !strings.Contains(err.Error(), "denied") {
		t.Errorf("error should name requires_one_of and denied, got: %v", err)
	}
}
