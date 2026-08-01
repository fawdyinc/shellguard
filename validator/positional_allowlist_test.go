package validator

import (
	"strings"
	"testing"

	"github.com/fawdyinc/shellguard/parser"
)

// validateCommand parses a full command string and validates it against the
// embedded registry, the way the server does.
func validateCommand(t *testing.T, command string) error {
	t.Helper()
	p, err := parser.Parse(command)
	if err != nil {
		t.Fatalf("parse %q: %v", command, err)
	}
	return ValidatePipeline(p, testRegistry(t))
}

// jcmd dispatches on a positional word rather than a flag, so flag validation
// cannot separate a thread dump from a forced GC. These pairs differ only at
// positional 1.
func TestPositionalAllowlistGatesJcmdDiagnosticCommands(t *testing.T) {
	allowed := []string{
		"jcmd 1234 Thread.print",
		"jcmd 1234 VM.flags",
		"jcmd 1234 VM.system_properties",
		"jcmd 1234 GC.heap_info",
		"jcmd 1234 GC.class_histogram",
	}
	for _, c := range allowed {
		if err := validateCommand(t, c); err != nil {
			t.Errorf("%q should be allowed: %v", c, err)
		}
	}

	denied := []string{
		"jcmd 1234 GC.run",
		"jcmd 1234 GC.heap_dump /tmp/heap.hprof",
		"jcmd 1234 VM.set_flag PrintGCDetails true",
		"jcmd 1234 JVMTI.agent_load /tmp/agent.so",
		"jcmd 1234 ManagementAgent.start",
		"jcmd 1234 JFR.start",
		"jcmd 1234 System.trim_native_heap",
	}
	for _, c := range denied {
		if err := validateCommand(t, c); err == nil {
			t.Errorf("%q should be denied: it changes the target JVM", c)
		}
	}
}

// The allowlist constrains one index. The pid at positional 0 and any arguments
// the diagnostic command takes after it stay unconstrained.
func TestPositionalAllowlistConstrainsOnlyItsIndex(t *testing.T) {
	if err := validateCommand(t, "jcmd 9999 VM.class_hierarchy java.lang.String"); err != nil {
		t.Errorf("arguments after the diagnostic command should be unconstrained: %v", err)
	}
	// Fewer positionals than the constrained index is not an error here; the
	// tool itself rejects those.
	if err := validateCommand(t, "jcmd 1234"); err != nil {
		t.Errorf("a pid with no diagnostic command should not trip the allowlist: %v", err)
	}
	if err := validateCommand(t, "jcmd -l"); err != nil {
		t.Errorf("jcmd -l has no positionals at all: %v", err)
	}
}

func TestPositionalAllowlistErrorNamesTheAllowedValues(t *testing.T) {
	err := validateCommand(t, "jcmd 1234 GC.run")
	if err == nil {
		t.Fatal("expected GC.run to be denied")
	}
	if !strings.Contains(err.Error(), "Thread.print") {
		t.Errorf("error should list the allowed values, got: %v", err)
	}
}

// -f reads diagnostic commands from a file, which would bypass the allowlist.
func TestJcmdCommandFileIsDenied(t *testing.T) {
	err := validateCommand(t, "jcmd -f /tmp/commands.txt")
	if err == nil {
		t.Fatal("jcmd -f bypasses the positional allowlist and must be denied")
	}
}
