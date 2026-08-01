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

func TestPowerShellCmdletsAreCaseInsensitive(t *testing.T) {
	cases := []string{
		"Get-Service", "get-service", "GET-SERVICE",
		"Get-CimInstance", "Where-Object", "Select-Object",
		"Format-Table", "Sort-Object", "Get-Process",
		"Get-WinEvent", "Get-ChildItem", "Get-Volume",
		"Get-NetTcpConnection", "Format-List", "Get-HotFix",
	}
	for _, name := range cases {
		if err := validateOne(t, name); err != nil {
			t.Errorf("validate %q: unexpected error %v", name, err)
		}
	}
}

func TestPosixCommandsRemainCaseSensitive(t *testing.T) {
	cases := []string{"LS", "Ls", "CAT", "Df", "UNAME"}
	for _, name := range cases {
		if err := validateOne(t, name); err == nil {
			t.Errorf("validate %q: expected rejection, POSIX lookup must stay case-sensitive", name)
		}
	}
}

func TestPowerShellUnknownFlagNotSplitIntoShortFlags(t *testing.T) {
	err := validateOne(t, "where-object", "-NotARealParameter")
	if err == nil {
		t.Fatal("expected rejection for unknown PowerShell parameter")
	}
	if strings.Contains(err.Error(), "'-N'") {
		t.Errorf("error split the parameter into a short flag cluster: %v", err)
	}
	if !strings.Contains(err.Error(), "-NotARealParameter") {
		t.Errorf("error should name the whole parameter, got: %v", err)
	}
}

func TestPosixFlagBundlingStillWorks(t *testing.T) {
	if err := validateOne(t, "ls", "-la"); err != nil {
		t.Fatalf("ls -la should still validate via flag bundling: %v", err)
	}
}

func TestPowerShellWildcardAllowedInFlagValue(t *testing.T) {
	if err := validateOne(t, "get-service", "-Name", "3D*"); err != nil {
		t.Fatalf("get-service -Name '3D*': unexpected error %v", err)
	}
	if err := validateOne(t, "Get-Service", "-Name", "Apache*"); err != nil {
		t.Fatalf("Get-Service -Name 'Apache*': unexpected error %v", err)
	}
}

func TestPowerShellCommaSeparatedFlagValueAccepted(t *testing.T) {
	// The parser currently collapses -Name 'a*','b*' into a single value rather
	// than an array. Correct tokenization is Phase 3 parser work; what matters
	// here is that the collapsed value no longer trips the glob check.
	if err := validateOne(t, "get-service", "-Name", `3D*","Apache*","SQL*`); err != nil {
		t.Fatalf("comma-separated -Name value: unexpected error %v", err)
	}
}

func TestPosixGlobInFlagValueStillRejected(t *testing.T) {
	// find -maxdepth takes a value and is not declared pattern_value, so a glob
	// there is exactly the case the check exists for. (The plan named grep -f,
	// but grep has no -f flag at all, so that case never reached the glob check.)
	err := validateOne(t, "find", "-maxdepth", "*")
	if err == nil {
		t.Fatal("expected glob rejection for POSIX flag value")
	}
	if !strings.Contains(err.Error(), "Glob pattern") {
		t.Errorf("expected glob rejection for POSIX flag value, got: %v", err)
	}
}

func TestRequiresOneOfPowerShell(t *testing.T) {
	m := &manifest.Manifest{
		Name:          "faketool.exe",
		Shell:         "powershell",
		RequiresOneOf: []string{"-l", "-r"},
		Flags: []manifest.Flag{
			{Flag: "-l"},
			{Flag: "-r", TakesValue: true},
		},
	}
	registry := map[string]*manifest.Manifest{"faketool.exe": m}
	validate := func(args ...string) error {
		p := &parser.Pipeline{Segments: []parser.PipelineSegment{{Command: "faketool.exe", Args: args}}}
		return ValidatePipeline(p, registry)
	}

	err := validate()
	if err == nil {
		t.Fatal("bare invocation should be rejected")
	}
	if !strings.Contains(err.Error(), "requires one of") {
		t.Errorf("error should explain the constraint, got: %v", err)
	}
	if !strings.Contains(err.Error(), "-l") || !strings.Contains(err.Error(), "-r") {
		t.Errorf("error should list the acceptable flags, got: %v", err)
	}

	if err := validate("-l"); err != nil {
		t.Errorf("-l should be accepted: %v", err)
	}
	if err := validate("-r", "IFW"); err != nil {
		t.Errorf("-r IFW should be accepted: %v", err)
	}
	// PowerShell parameter names are case-insensitive.
	if err := validate("-L"); err != nil {
		t.Errorf("-L should be accepted for a powershell manifest: %v", err)
	}
}

func TestRequiresOneOfPosixIsCaseSensitive(t *testing.T) {
	m := &manifest.Manifest{
		Name:          "faketool",
		RequiresOneOf: []string{"-l"},
		Flags:         []manifest.Flag{{Flag: "-l"}},
	}
	registry := map[string]*manifest.Manifest{"faketool": m}
	validate := func(args ...string) error {
		p := &parser.Pipeline{Segments: []parser.PipelineSegment{{Command: "faketool", Args: args}}}
		return ValidatePipeline(p, registry)
	}

	if err := validate("-l"); err != nil {
		t.Errorf("-l should be accepted: %v", err)
	}
	err := validate("-L")
	if err == nil {
		t.Fatal("-L should be rejected for a POSIX manifest")
	}
	if !strings.Contains(err.Error(), "requires one of") {
		t.Errorf("expected the requires_one_of message, got: %v", err)
	}
}

func TestRequiresOneOfAbsentIsUnconstrained(t *testing.T) {
	m := &manifest.Manifest{
		Name:  "freetool",
		Flags: []manifest.Flag{{Flag: "-l"}},
	}
	registry := map[string]*manifest.Manifest{"freetool": m}
	p := &parser.Pipeline{Segments: []parser.PipelineSegment{{Command: "freetool"}}}
	if err := ValidatePipeline(p, registry); err != nil {
		t.Errorf("a manifest without requires_one_of must accept bare invocation: %v", err)
	}
}
