package validator

import (
	"strings"
	"testing"

	"github.com/fawdyinc/shellguard/manifest"
	"github.com/fawdyinc/shellguard/parser"
)

func testRegistry(t *testing.T) map[string]*manifest.Manifest {
	t.Helper()
	registry, err := manifest.LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded() error = %v", err)
	}
	return registry
}

func validateOne(t *testing.T, command string, args ...string) error {
	t.Helper()
	p := &parser.Pipeline{Segments: []parser.PipelineSegment{{Command: command, Args: args}}}
	return ValidatePipeline(p, testRegistry(t))
}

func TestAllowsSimpleCommand(t *testing.T) {
	if err := validateOne(t, "ls", "/tmp"); err != nil {
		t.Fatalf("validate ls: %v", err)
	}
}

func TestRejectsDeniedCommand(t *testing.T) {
	err := validateOne(t, "rm", "/tmp/file")
	if err == nil {
		t.Fatal("expected deny error for rm")
	}
}

func TestRejectsUnknownCommand(t *testing.T) {
	err := validateOne(t, "definitely-not-a-command")
	if err == nil {
		t.Fatal("expected unknown command error")
	}
}

func TestSuggestsClosestCmdlet(t *testing.T) {
	err := validateOne(t, "get-procces") // typo for get-process
	if err == nil {
		t.Fatal("expected unknown command error with suggestion")
	}
	if !strings.Contains(err.Error(), "Did you mean") || !strings.Contains(err.Error(), "get-process") {
		t.Errorf("expected suggestion for get-process, got: %v", err)
	}
}

func TestNoSuggestionForFarCommand(t *testing.T) {
	// "zzz" is too far from any allowed cmdlet — no suggestion.
	err := validateOne(t, "zzz")
	if err == nil {
		t.Fatal("expected unknown command error")
	}
	if strings.Contains(err.Error(), "Did you mean") {
		t.Errorf("did not expect suggestion for zzz, got: %v", err)
	}
}

func TestRejectsDeniedFlag(t *testing.T) {
	err := validateOne(t, "tail", "-f", "/var/log/syslog")
	if err == nil {
		t.Fatal("expected denied flag error")
	}
}

func TestRejectsUnknownFlag(t *testing.T) {
	err := validateOne(t, "grep", "--nope", "error", "/var/log/syslog")
	if err == nil {
		t.Fatal("expected unknown flag error")
	}
}

func TestAllowsCombinedShortFlags(t *testing.T) {
	if err := validateOne(t, "grep", "-irn", "error", "/var/log/syslog"); err != nil {
		t.Fatalf("validate grep combined flags: %v", err)
	}
}

func TestSudoAllowsValidCommand(t *testing.T) {
	if err := validateOne(t, "sudo", "ls", "/tmp"); err != nil {
		t.Fatalf("sudo ls should be allowed: %v", err)
	}
}

func TestSudoUAllowsValidCommand(t *testing.T) {
	if err := validateOne(t, "sudo", "-u", "postgres", "psql", "-c", "SELECT 1"); err != nil {
		t.Fatalf("sudo -u postgres psql should be allowed: %v", err)
	}
}

func TestSudoRejectsDeniedCommand(t *testing.T) {
	err := validateOne(t, "sudo", "rm", "/tmp/file")
	if err == nil {
		t.Fatal("expected sudo rm to be rejected")
	}
}

func TestSudoURejectsDeniedCommand(t *testing.T) {
	err := validateOne(t, "sudo", "-u", "nobody", "rm", "/tmp/file")
	if err == nil {
		t.Fatal("expected sudo -u nobody rm to be rejected")
	}
}

func TestSudoRejectsUnknownCommand(t *testing.T) {
	err := validateOne(t, "sudo", "definitely-not-a-command")
	if err == nil {
		t.Fatal("expected sudo with unknown command to be rejected")
	}
}

func TestSudoRejectsNoArgs(t *testing.T) {
	err := validateOne(t, "sudo")
	if err == nil {
		t.Fatal("expected bare sudo to be rejected")
	}
}

func TestSudoURejectsNoCommand(t *testing.T) {
	err := validateOne(t, "sudo", "-u", "postgres")
	if err == nil {
		t.Fatal("expected sudo -u with no command to be rejected")
	}
}

func TestValidatesSubcommands(t *testing.T) {
	if err := validateOne(t, "docker", "ps"); err != nil {
		t.Fatalf("validate docker ps: %v", err)
	}

	if err := validateOne(t, "docker", "ps", "--format", "{{.ID}}"); err != nil {
		t.Fatalf("validate docker ps --format: %v", err)
	}

	if err := validateOne(t, "docker", "stats", "--no-stream"); err != nil {
		t.Fatalf("validate docker stats --no-stream: %v", err)
	}

	err := validateOne(t, "docker", "run", "alpine")
	if err == nil {
		t.Fatal("expected docker run to be rejected")
	}
}

func TestValidatesAwsServiceSubcommands(t *testing.T) {
	if err := validateOne(t, "aws", "ec2", "describe-instances"); err != nil {
		t.Fatalf("validate aws ec2 describe-instances: %v", err)
	}
}

func TestPsqlRequiresCFlag(t *testing.T) {
	err := validateOne(t, "psql", "-d", "app")
	if err == nil {
		t.Fatal("expected psql without -c to be rejected")
	}
}

func TestPsqlSQLReadOnlyEnforced(t *testing.T) {
	if err := validateOne(t, "psql", "-c", "SELECT 1"); err != nil {
		t.Fatalf("expected SELECT to pass: %v", err)
	}

	err := validateOne(t, "psql", "-c", "DELETE FROM users")
	if err == nil {
		t.Fatal("expected DELETE to be rejected")
	}
}

func TestGlobRules(t *testing.T) {
	if err := validateOne(t, "find", "/var/log", "-name", "*.log"); err != nil {
		t.Fatalf("find -name *.log should be allowed: %v", err)
	}

	err := validateOne(t, "grep", "error", "*.log")
	if err == nil {
		t.Fatal("expected positional glob to be rejected")
	}
}

func TestRestrictedPathRejected(t *testing.T) {
	err := validateOne(t, "find", "/proc/kcore")
	if err == nil {
		t.Fatal("expected restricted path to be rejected")
	}
}

func TestUnzipRequiresSafeMode(t *testing.T) {
	err := validateOne(t, "unzip", "archive.zip")
	if err == nil {
		t.Fatal("expected unzip without -l/-p to be rejected")
	}

	if err := validateOne(t, "unzip", "-l", "archive.zip"); err != nil {
		t.Fatalf("unzip -l should be allowed: %v", err)
	}
}

func TestTarExtractRequiresStdout(t *testing.T) {
	err := validateOne(t, "tar", "-xf", "archive.tar")
	if err == nil {
		t.Fatal("expected tar -x without -O to be rejected")
	}

	if err := validateOne(t, "tar", "-xf", "archive.tar", "-O"); err != nil {
		t.Fatalf("tar -xf archive.tar -O should be allowed: %v", err)
	}
}

func TestNumericCountShorthandAllowed(t *testing.T) {
	if err := validateOne(t, "head", "-20", "/var/log/syslog"); err != nil {
		t.Fatalf("head -20 should be allowed: %v", err)
	}
}

func TestSubcommandParentBareFlags(t *testing.T) {
	cases := [][]string{
		{"docker", "--version"},
		{"docker", "-v"},
		{"docker", "--help"},
		{"systemctl", "--failed"},
		{"systemctl", "--no-pager"},
		{"systemctl", "--state=failed"},
		{"systemctl", "--type", "service"},
		{"kubectl", "--version"},
		{"aws", "--version"},
		{"svn", "--version"},
		{"podman", "--version"},
	}
	for _, c := range cases {
		if err := validateOne(t, c[0], c[1:]...); err != nil {
			t.Errorf("expected %v to validate, got: %v", c, err)
		}
	}
}

func TestSubcommandParentRejectsUnknownFlag(t *testing.T) {
	err := validateOne(t, "docker", "--definitely-not-real")
	if err == nil {
		t.Fatal("expected unknown parent flag to be rejected")
	}
}

func TestSubcommandRoutingPreserved(t *testing.T) {
	if err := validateOne(t, "docker", "ps"); err != nil {
		t.Fatalf("docker ps should still route to subcommand: %v", err)
	}
	if err := validateOne(t, "systemctl", "list-units", "--state=failed"); err != nil {
		t.Fatalf("systemctl list-units --state=failed: %v", err)
	}
	err := validateOne(t, "docker", "run", "alpine")
	if err == nil {
		t.Fatal("expected docker run to still be rejected")
	}
}

func TestSystemctlListUnitsExtendedFlags(t *testing.T) {
	cases := [][]string{
		{"systemctl", "list-units", "--state=failed"},
		{"systemctl", "list-units", "--all"},
		{"systemctl", "list-units", "--plain"},
		{"systemctl", "list-units", "--no-legend"},
		{"systemctl", "list-units", "--reverse"},
		{"systemctl", "list-units", "--type=service", "--state=running"},
	}
	for _, c := range cases {
		if err := validateOne(t, c[0], c[1:]...); err != nil {
			t.Errorf("expected %v to validate, got: %v", c, err)
		}
	}
}

// TestSubcommandParentFlagFirstBypass_Rejected covers the parent-flag-first
// bypass: prepending an allowed parent flag must NOT cause a denied
// subcommand to fall through to the parent's permissive validateArgs.
func TestSubcommandParentFlagFirstBypass_Rejected(t *testing.T) {
	cases := [][]string{
		// systemctl: parent flags do not exit early — must still dispatch to
		// the (read-only) subcommand allowlist.
		{"systemctl", "--no-pager", "start", "sshd"},
		{"systemctl", "--no-pager", "stop", "sshd"},
		{"systemctl", "--no-pager", "restart", "sshd"},
		{"systemctl", "--no-pager", "enable", "sshd"},
		{"systemctl", "--no-pager", "disable", "sshd"},
		{"systemctl", "--no-pager", "mask", "sshd"},
		{"systemctl", "--no-pager", "daemon-reload"},
		{"systemctl", "--no-pager", "kill", "sshd"},
		{"systemctl", "--no-pager", "isolate", "rescue.target"},
		{"systemctl", "--user", "start", "sshd"},
		{"systemctl", "--system", "start", "sshd"},
		{"systemctl", "--state=running", "start", "sshd"},
		{"systemctl", "--type", "service", "start", "sshd"},
		// defaults: -currentHost / -host modifiers must not allow write/delete
		// to bypass the read-only subcommand allowlist on macOS.
		{"defaults", "-currentHost", "write", "com.apple.x", "key", "value"},
		{"defaults", "-currentHost", "delete", "com.apple.dock"},
		{"defaults", "-host", "myhost", "write", "com.apple.x", "key", "value"},
		{"defaults", "-host", "myhost", "delete", "com.apple.dock"},
		{"defaults", "-host", "myhost", "import", "com.apple.x", "/tmp/file"},
	}
	for _, c := range cases {
		if err := validateOne(t, c[0], c[1:]...); err == nil {
			t.Errorf("expected %v to be rejected (parent-flag-first bypass), but it passed", c)
		}
	}
}

// TestSubcommandParentFlagsBeforeAllowedSubcommand verifies the fix preserves
// legitimate use: parent flags followed by a registered (read-only)
// subcommand should still validate.
func TestSubcommandParentFlagsBeforeAllowedSubcommand(t *testing.T) {
	cases := [][]string{
		{"systemctl", "--no-pager", "status", "sshd"},
		{"systemctl", "--no-pager", "list-units"},
		{"systemctl", "--user", "status", "sshd"},
		{"systemctl", "--state=failed", "list-units"},
		{"systemctl", "--type", "service", "list-units"},
	}
	for _, c := range cases {
		if err := validateOne(t, c[0], c[1:]...); err != nil {
			t.Errorf("expected %v to validate, got: %v", c, err)
		}
	}
}

// TestCommandBuiltinRequiresIntrospectionFlag verifies the `command` builtin
// allowlist bypass is closed — bare `command <cmd>` would actually execute
// <cmd> and defeat every other manifest restriction.
func TestCommandBuiltinRequiresIntrospectionFlag(t *testing.T) {
	rejected := [][]string{
		{"command", "rm", "/tmp/foo"},
		{"command", "kill", "1"},
		{"command", "sh", "/tmp/script"},
		{"command", "cat", "/etc/shadow"},
		{"command"}, // no args at all
	}
	for _, c := range rejected {
		if err := validateOne(t, c[0], c[1:]...); err == nil {
			t.Errorf("expected %v to be rejected (command without -v/-V), but it passed", c)
		}
	}

	accepted := [][]string{
		{"command", "-v", "ls"},
		{"command", "-V", "ls"},
	}
	for _, c := range accepted {
		if err := validateOne(t, c[0], c[1:]...); err != nil {
			t.Errorf("expected %v to validate, got: %v", c, err)
		}
	}
}

// TestSudoCommandBuiltinBypass_Rejected: sudo wrapping must not let
// `command` skip the introspection-flag requirement.
func TestSudoCommandBuiltinBypass_Rejected(t *testing.T) {
	if err := validateOne(t, "sudo", "command", "rm", "/tmp/foo"); err == nil {
		t.Error("expected sudo command rm to be rejected, but it passed")
	}
}

func TestNewTier1Manifests(t *testing.T) {
	cases := [][]string{
		{"which", "ls"},
		{"which", "-a", "go"},
		{"command", "-v", "ls"},
		{"command", "-V", "go"},
		{"podman", "ps"},
		{"podman", "ps", "-a"},
		{"podman", "inspect", "container"},
		{"podman", "logs", "--tail", "100", "container"},
		{"podman", "stats", "--no-stream"},
	}
	for _, c := range cases {
		if err := validateOne(t, c[0], c[1:]...); err != nil {
			t.Errorf("expected %v to validate, got: %v", c, err)
		}
	}
}

func TestNewTier2SafeCommands(t *testing.T) {
	cases := [][]string{
		{"id"},
		{"id", "-u"},
		{"groups"},
		{"whoami"},
		{"tty"},
		{"arch"},
		{"date"},
		{"date", "-u"},
		{"users"},
		{"locale"},
		{"locale", "-a"},
		{"getent", "hosts", "localhost"},
		{"getconf", "PATH"},
		{"realpath", "/tmp"},
		{"basename", "/usr/bin/go"},
		{"dirname", "/usr/bin/go"},
		{"mountpoint", "-q", "/"},
		{"tree", "-L", "2", "/tmp"},
		{"traceroute", "-n", "example.com"},
		{"mtr", "-r", "-c", "3", "example.com"},
		{"host", "example.com"},
		{"whois", "example.com"},
		{"arp", "-a"},
		{"sw_vers"},
		{"sw_vers", "-productVersion"},
		{"system_profiler", "-listDataTypes"},
	}
	for _, c := range cases {
		if err := validateOne(t, c[0], c[1:]...); err != nil {
			t.Errorf("expected %v to validate, got: %v", c, err)
		}
	}
}

func TestSubcommandAwareTier2(t *testing.T) {
	cases := [][]string{
		{"defaults", "read", "com.apple.dock"},
		{"defaults", "domains"},
		{"launchctl", "list"},
		{"launchctl", "print", "system"},
		{"sysctl", "-a"},
		{"sysctl", "-n", "kern.ostype"},
	}
	for _, c := range cases {
		if err := validateOne(t, c[0], c[1:]...); err != nil {
			t.Errorf("expected %v to validate, got: %v", c, err)
		}
	}
}

func TestSysctlWriteDenied(t *testing.T) {
	err := validateOne(t, "sysctl", "-w", "net.ipv4.tcp_syncookies=1")
	if err == nil {
		t.Fatal("expected sysctl -w to be rejected")
	}
}

func TestArpWriteDenied(t *testing.T) {
	err := validateOne(t, "arp", "-d", "10.0.0.1")
	if err == nil {
		t.Fatal("expected arp -d to be rejected")
	}
}

func TestDateSetDenied(t *testing.T) {
	err := validateOne(t, "date", "-s", "2026-01-01")
	if err == nil {
		t.Fatal("expected date -s to be rejected")
	}
}
