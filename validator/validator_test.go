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

func TestRequiresOneOfValueNotMistakenForFlag(t *testing.T) {
	// When -x takes a value and -l is passed as that value, it must not
	// satisfy a requires_one_of constraint for -l.
	m := &manifest.Manifest{
		Name:          "faketool",
		RequiresOneOf: []string{"-l"},
		Flags: []manifest.Flag{
			{Flag: "-l"},
			{Flag: "-x", TakesValue: true},
		},
	}
	registry := map[string]*manifest.Manifest{"faketool": m}
	validate := func(args ...string) error {
		p := &parser.Pipeline{Segments: []parser.PipelineSegment{{Command: "faketool", Args: args}}}
		return ValidatePipeline(p, registry)
	}

	// -l as the value for -x should be rejected (constraint not met)
	err := validate("-x", "-l")
	if err == nil {
		t.Fatal("tool -x -l should be rejected: -l is a value, not a flag")
	}
	if !strings.Contains(err.Error(), "requires one of") {
		t.Errorf("expected requires_one_of error, got: %v", err)
	}

	// -l genuinely as a flag should be accepted
	if err := validate("-l", "-x", "value"); err != nil {
		t.Errorf("-l -x value should be accepted: %v", err)
	}
}

func TestRequiresOneOfInlineValueSyntax(t *testing.T) {
	// Inline value syntax (--flag=value) should satisfy requires_one_of.
	m := &manifest.Manifest{
		Name:          "faketool",
		RequiresOneOf: []string{"--level"},
		Flags: []manifest.Flag{
			{Flag: "--level", TakesValue: true},
			{Flag: "-x", TakesValue: true},
		},
	}
	registry := map[string]*manifest.Manifest{"faketool": m}
	validate := func(args ...string) error {
		p := &parser.Pipeline{Segments: []parser.PipelineSegment{{Command: "faketool", Args: args}}}
		return ValidatePipeline(p, registry)
	}

	// Inline form should be accepted
	if err := validate("--level=5"); err != nil {
		t.Errorf("--level=5 should be accepted: %v", err)
	}

	// Mixed forms should be accepted
	if err := validate("-x", "foo", "--level=5"); err != nil {
		t.Errorf("-x foo --level=5 should be accepted: %v", err)
	}
}

func TestRequiresOneOfPowerShellCommonParamValue(t *testing.T) {
	// When a PowerShell common parameter takes a value, that value is consumed
	// and should not satisfy a requires_one_of constraint, even if it looks
	// like a required flag.
	m := &manifest.Manifest{
		Name:          "get-service",
		Shell:         "powershell",
		RequiresOneOf: []string{"-Force"},
		Flags: []manifest.Flag{
			{Flag: "-Force"},
			{Flag: "-Name", TakesValue: true},
		},
	}
	registry := map[string]*manifest.Manifest{"get-service": m}
	validate := func(args ...string) error {
		p := &parser.Pipeline{Segments: []parser.PipelineSegment{{Command: "get-service", Args: args}}}
		return ValidatePipeline(p, registry)
	}

	// -Force as the value for -ErrorAction (a common param that takes a value)
	// should be rejected — the constraint is not met
	err := validate("-ErrorAction", "-Force")
	if err == nil {
		t.Fatal("get-service -ErrorAction -Force should be rejected: -Force is a value, not a flag")
	}
	if !strings.Contains(err.Error(), "requires one of") {
		t.Errorf("expected requires_one_of error, got: %v", err)
	}

	// -Force genuinely as a flag should be accepted
	if err := validate("-Force", "-ErrorAction", "Stop"); err != nil {
		t.Errorf("-Force -ErrorAction Stop should be accepted: %v", err)
	}

	// Common param without value should not interfere
	if err := validate("-Force", "-Verbose"); err != nil {
		t.Errorf("-Force -Verbose should be accepted: %v", err)
	}
}

func TestRequiresOneOfPosixIgnoresCommonParams(t *testing.T) {
	// POSIX manifests have no special handling for -ErrorAction etc.
	// They are treated as ordinary flags, unknown and rejected.
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

	// -ErrorAction is not a flag in the manifest, so it's rejected as unknown
	// (not special-cased like in PowerShell)
	err := validate("-ErrorAction", "-l")
	if err == nil {
		t.Fatal("faketool -ErrorAction -l should be rejected: -ErrorAction is unknown in POSIX manifest")
	}
	// Error should be about unknown flag, not requires_one_of
	if strings.Contains(err.Error(), "requires one of") {
		t.Errorf("POSIX should reject -ErrorAction as unknown flag, not requires_one_of issue, got: %v", err)
	}
}

func TestBlockedExecutableMessageIsTerminal(t *testing.T) {
	// NotARealTool.exe stands in for an unmanifested executable. DSCheckLS.exe
	// filled this role until Task 6 gave it a real manifest (requires_one_of:
	// -l is now allowed), so this test needed a name that stays unmanifested.
	err := validateOne(t, "NotARealTool.exe", "-l")
	if err == nil {
		t.Fatal("expected rejection for an unmanifested executable")
	}
	msg := err.Error()
	// Names the whole binary, not a fragment.
	if !strings.Contains(msg, "NotARealTool.exe") {
		t.Errorf("error should name the binary, got: %v", msg)
	}
	// Forecloses the alternatives so the agent stops enumerating them.
	for _, alt := range []string{"&", "Start-Process", "cmd /c"} {
		if !strings.Contains(msg, alt) {
			t.Errorf("error should foreclose %q, got: %v", alt, msg)
		}
	}
	// Must not offer a fuzzy suggestion - that invites another attempt.
	if strings.Contains(msg, "Did you mean") {
		t.Errorf("blocked executable must not suggest an alternative command, got: %v", msg)
	}
}

func TestBlockedExecutableExtensions(t *testing.T) {
	blocked := []string{"foo.exe", "FOO.EXE", "foo.bat", "foo.cmd", "foo.com", "foo.ps1"}
	for _, name := range blocked {
		if !blockedExecutable(name) {
			t.Errorf("blockedExecutable(%q) = false, want true", name)
		}
	}
	notBlocked := []string{"ls", "get-service", "foo.exec", "exe", "foo.executable", "foo"}
	for _, name := range notBlocked {
		if blockedExecutable(name) {
			t.Errorf("blockedExecutable(%q) = true, want false", name)
		}
	}
}

// A normal unknown command keeps its existing message, including the fuzzy hint.
func TestUnknownNonExecutableKeepsSuggestion(t *testing.T) {
	err := validateOne(t, "get-servic")
	if err == nil {
		t.Fatal("expected rejection")
	}
	if !strings.Contains(err.Error(), "Did you mean") {
		t.Errorf("non-executable typo should still get a suggestion, got: %v", err)
	}
}

func TestTwoLevelSubcommandGeneralized(t *testing.T) {
	sub := &manifest.Manifest{Name: "abaqus_licensing_dslsstat", Shell: "powershell"}
	registry := map[string]*manifest.Manifest{"abaqus_licensing_dslsstat": sub}
	p := &parser.Pipeline{Segments: []parser.PipelineSegment{
		{Command: "abaqus", Args: []string{"licensing", "dslsstat"}},
	}}
	if err := ValidatePipeline(p, registry); err != nil {
		t.Fatalf("abaqus licensing dslsstat should resolve: %v", err)
	}
}

// Dropping the aws special-case must not change one-level dispatch.
func TestOneLevelSubcommandsUnchanged(t *testing.T) {
	cases := []struct {
		command string
		args    []string
	}{
		{"docker", []string{"ps"}},
		{"systemctl", []string{"status"}},
		{"kubectl", []string{"get", "pods"}},
	}
	for _, tc := range cases {
		if err := validateOne(t, tc.command, tc.args...); err != nil {
			t.Errorf("%s %v: unexpected error %v", tc.command, tc.args, err)
		}
	}
}

func TestAwsTwoLevelStillWorks(t *testing.T) {
	if err := validateOne(t, "aws", "ec2", "describe-instances"); err != nil {
		t.Errorf("aws ec2 describe-instances: unexpected error %v", err)
	}
}

func TestDslsstatValidatesEndToEnd(t *testing.T) {
	if err := validateOne(t, "abaqus", "licensing", "dslsstat"); err != nil {
		t.Fatalf("abaqus licensing dslsstat: unexpected error %v", err)
	}
	if err := validateOne(t, "abaqus", "licensing", "dslsstat", "-usage"); err != nil {
		t.Fatalf("with -usage: unexpected error %v", err)
	}
	if err := validateOne(t, "abaqus", "licensing", "dslsstat", "-server", "jupiter:4085"); err != nil {
		t.Fatalf("with -server: unexpected error %v", err)
	}
	// A solve invocation must stay refused. validateOne builds the pipeline
	// directly, bypassing the parser, so this genuinely exercises subcommand
	// dispatch - unlike the corpus entry for the same command, which the parser
	// rejects earlier on the "=" token.
	err := validateOne(t, "abaqus", "job=beam")
	if err == nil {
		t.Fatal("abaqus job=beam must be refused")
	}
	if !strings.Contains(err.Error(), "subcommand") {
		t.Errorf("expected a subcommand rejection, got: %v", err)
	}
}

func TestDSCheckLSRequiresASafeMode(t *testing.T) {
	// Bare invocation requests and releases a license - refused.
	err := validateOne(t, "DSCheckLS.exe")
	if err == nil {
		t.Fatal("bare DSCheckLS.exe must be refused - it pulls a license")
	}
	if !strings.Contains(err.Error(), "requires one of") {
		t.Errorf("expected the requires_one_of message, got: %v", err)
	}

	for _, args := range [][]string{{"-l"}, {"-h"}, {"-r", "IFW"}} {
		if err := validateOne(t, "DSCheckLS.exe", args...); err != nil {
			t.Errorf("DSCheckLS.exe %v: unexpected error %v", args, err)
		}
	}

	// Lowercase and mixed case both resolve (parser lowercases; PowerShell
	// flag matching is case-insensitive).
	if err := validateOne(t, "dscheckls.exe", "-L"); err != nil {
		t.Errorf("dscheckls.exe -L: unexpected error %v", err)
	}
}

func TestDSCheckLSTokenFlagDenied(t *testing.T) {
	err := validateOne(t, "DSCheckLS.exe", "-t", "IFW")
	if err == nil {
		t.Fatal("-t consumes a license and must be denied")
	}
	msg := err.Error()
	if !strings.Contains(msg, "30 days") {
		t.Errorf("denial should explain the 30-day lock, got: %v", msg)
	}
	if !strings.Contains(msg, "-r") {
		t.Errorf("denial should point at -r as the safe alternative, got: %v", msg)
	}
}

// A denied flag must not reach the vendor binary disguised as another flag's
// value. -r takes_value, so DSCheckLS.exe -r -t previously let -t through as
// -r's value without ever being flag-validated - PowerShellQuote then passes
// it unquoted, so the wire command literally contains -t. -t requests and
// consumes a Dassault license, locking it for 30 days.
func TestDSCheckLSTokenFlagCannotBeSmuggledAsAValue(t *testing.T) {
	cases := [][]string{
		{"-r", "-t"},
		{"-r", "-t", "IFW"},
		{"-l", "-r", "-t"},
		{"-r", "-T"}, // case variant; dscheckls.exe is shell: powershell
	}
	for _, args := range cases {
		err := validateOne(t, "DSCheckLS.exe", args...)
		if err == nil {
			t.Fatalf("DSCheckLS.exe %v: expected rejection, -t must not reach the wire as a value", args)
		}
		msg := err.Error()
		// PowerShell flag matching is case-insensitive (dscheckls.exe is
		// shell: powershell), so the -r -T case variant reports the value as
		// typed ('-T') rather than as declared ('-t'). Compare case-insensitively.
		if !strings.Contains(strings.ToLower(msg), "-t") {
			t.Errorf("DSCheckLS.exe %v: error should name -t, got: %v", args, msg)
		}
		if !strings.Contains(msg, "30 days") {
			t.Errorf("DSCheckLS.exe %v: error should carry the 30-day reason, got: %v", args, msg)
		}
	}
}

// A legitimate value for -r must still be accepted - only values that
// exactly name a denied flag are caught.
func TestDSCheckLSLegitimateValueStillAccepted(t *testing.T) {
	if err := validateOne(t, "DSCheckLS.exe", "-r", "IFW"); err != nil {
		t.Errorf("DSCheckLS.exe -r IFW: unexpected error %v", err)
	}
}

// Same smuggling mechanism, POSIX side: tail -n takes a value, and -f is
// denied (follow mode). `tail -n -f` is malformed anyway - it means "print
// the last -f lines" - so rejecting it is correct, not a regression.
func TestTailFollowCannotBeSmuggledAsNValue(t *testing.T) {
	err := validateOne(t, "tail", "-n", "-f")
	if err == nil {
		t.Fatal("tail -n -f: expected rejection, -f must not reach the wire as -n's value")
	}
	if !strings.Contains(err.Error(), "-f") {
		t.Errorf("tail -n -f: error should name -f, got: %v", err)
	}
}

func TestDangerousWindowsBinariesDeniedWithReason(t *testing.T) {
	cases := map[string]string{
		"cmd.exe":        "shell",    // already manifested
		"powershell.exe": "shell",    // already manifested
		"reg.exe":        "registry", // added by this task
		"net.exe":        "network",  // added by this task
	}
	for name, wantWord := range cases {
		err := validateOne(t, name)
		if err == nil {
			t.Errorf("%s must be denied", name)
			continue
		}
		msg := strings.ToLower(err.Error())
		if !strings.Contains(msg, wantWord) {
			t.Errorf("%s: denial should mention %q, got: %v", name, wantWord, err)
		}
		// A specific reason, not the generic blocked-executable message.
		if strings.Contains(err.Error(), "is not in the allowed tool list") {
			t.Errorf("%s: should have a specific reason, got the generic message: %v", name, err)
		}
	}
}

// TestGetPSDriveProviderFlag covers a command from the recorded 3DX session.
// The manifest declared `flags: []`, so -PSProvider was rejected even though
// the command parsed — the parser corpus called this entry "already works",
// which was true of the parser and false of the validator.
func TestGetPSDriveProviderFlag(t *testing.T) {
	if err := validateOne(t, "Get-PSDrive", "-PSProvider", "FileSystem"); err != nil {
		t.Errorf("Get-PSDrive -PSProvider FileSystem: unexpected error %v", err)
	}
	if err := validateOne(t, "get-psdrive"); err != nil {
		t.Errorf("bare get-psdrive: unexpected error %v", err)
	}
	if err := validateOne(t, "Get-PSDrive", "-NotAReal", "x"); err == nil {
		t.Error("unknown flag should still be rejected")
	}
}

// TestIPLiteralReachesValidator confirms the parser change lands end to end:
// an IPv4 flag value now survives parse and validate together.
func TestIPLiteralReachesValidator(t *testing.T) {
	p, err := parser.ParsePowerShell("Test-NetConnection -ComputerName 127.0.0.1 -Port 443")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := ValidatePipeline(p, testRegistry(t)); err != nil {
		t.Errorf("validate: unexpected error %v", err)
	}
}
