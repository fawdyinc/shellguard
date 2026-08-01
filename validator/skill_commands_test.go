package validator

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/fawdyinc/shellguard/manifest"
	"github.com/fawdyinc/shellguard/parser"
)

// TestSkillCommandsValidate asserts that every command Fawdy's skills tell the
// agent to run is actually permitted by this registry.
//
// A skill recommending a command the guard rail refuses is worse than a skill
// that says nothing: the agent follows the instruction, gets refused, and burns
// turns rediscovering the limit. That shipped -- the apache skill's whole log
// analysis section was built on awk, which is denied because awk can execute
// commands, and java-jvm recommended `kill -3` for a thread dump. Both were
// found by hand-checking, which is exactly the thing that does not happen
// twice. Hence this test.
//
// The corpus is a committed fixture rather than a live read of the skills:
// fawdy-legacy is a separate repository and is not checked out in CI, and it
// pins a *released* shellguard, so a test living there could never see an
// unreleased manifest. Regenerate the fixture with
// scripts/extract-skill-commands.py after changing either side.
func TestSkillCommandsValidate(t *testing.T) {
	entries := loadSkillCommands(t)
	if len(entries) < 100 {
		t.Fatalf("corpus has only %d commands; extraction is probably broken", len(entries))
	}

	registry := testRegistry(t)
	byReason := map[string][]string{}

	for _, e := range entries {
		if err := validateForShell(e.shell, e.command, registry); err != nil {
			key := fmt.Sprintf("%s\n      %s", err.Error(), e.source+"  "+e.command)
			byReason[err.Error()] = append(byReason[err.Error()], "  "+e.source+"\n      "+e.command)
			_ = key
		}
	}

	if len(byReason) == 0 {
		return
	}

	reasons := make([]string, 0, len(byReason))
	for r := range byReason {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)

	var b strings.Builder
	total := 0
	for _, r := range reasons {
		total += len(byReason[r])
	}
	fmt.Fprintf(&b, "%d skill-recommended commands are refused by the registry.\n", total)
	b.WriteString("Either the manifest is missing/too strict, or the skill should not be recommending this.\n\n")
	for _, r := range reasons {
		fmt.Fprintf(&b, "%s\n", r)
		sort.Strings(byReason[r])
		for _, loc := range byReason[r] {
			fmt.Fprintf(&b, "%s\n", loc)
		}
		b.WriteString("\n")
	}
	t.Fatal(b.String())
}

// validateForShell runs a command through the parser and registry scope that
// its host would use. PowerShell has its own parser, and ScopeRegistry hides
// the manifests that do not apply to the target shell.
func validateForShell(shell, command string, registry map[string]*manifest.Manifest) error {
	var (
		pipeline *parser.Pipeline
		err      error
	)
	if shell == "powershell" {
		pipeline, err = parser.ParsePowerShell(command)
	} else {
		pipeline, err = parser.Parse(command)
	}
	if err != nil {
		return err
	}
	return ValidatePipeline(pipeline, ScopeRegistry(registry, shell))
}

type skillCommand struct {
	source  string
	shell   string
	command string
}

func loadSkillCommands(t *testing.T) []skillCommand {
	t.Helper()
	f, err := os.Open("testdata/skill-commands.txt")
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer func() { _ = f.Close() }()

	var entries []skillCommand
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) != 3 {
			t.Fatalf("malformed corpus line: %q", line)
		}
		entries = append(entries, skillCommand{source: parts[0], shell: parts[1], command: parts[2]})
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	return entries
}
