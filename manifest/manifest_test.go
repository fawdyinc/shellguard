package manifest

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"
)

func mustLoadEmbedded(t *testing.T) map[string]*Manifest {
	t.Helper()

	registry, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded() error = %v", err)
	}
	return registry
}

func TestLoadEmbeddedCountAndNameMatch(t *testing.T) {
	registry := mustLoadEmbedded(t)

	if got, want := len(registry), 294; got != want {
		t.Fatalf("len(registry) = %d, want %d", got, want)
	}

	for name, m := range registry {
		if m.Name != name {
			t.Fatalf("manifest key/name mismatch: key=%q name=%q", name, m.Name)
		}
	}
}

func TestLoadEmbeddedSchemaSkipped(t *testing.T) {
	registry := mustLoadEmbedded(t)
	if _, ok := registry["_schema"]; ok {
		t.Fatal("_schema should never be loaded as a manifest")
	}
}

func TestDenyManifestReasonsAndCount(t *testing.T) {
	registry := mustLoadEmbedded(t)

	denyCount := 0
	for name, m := range registry {
		if !m.Deny {
			continue
		}
		denyCount++
		if m.Reason == "" {
			t.Fatalf("deny manifest %q missing reason", name)
		}
	}

	if got, want := denyCount, 123; got != want {
		t.Fatalf("deny manifest count = %d, want %d", got, want)
	}
}

func TestDeniedFlagsHaveReasons(t *testing.T) {
	registry := mustLoadEmbedded(t)

	for name, m := range registry {
		for _, f := range m.Flags {
			if f.Deny && f.Reason == "" {
				t.Fatalf("denied flag %q in %q missing reason", f.Flag, name)
			}
		}
	}
}

func TestPatternValueFlagsRequireTakesValue(t *testing.T) {
	registry := mustLoadEmbedded(t)

	for name, m := range registry {
		for _, f := range m.Flags {
			if f.PatternValue && !f.TakesValue {
				t.Fatalf("flag %q in %q has pattern_value but not takes_value", f.Flag, name)
			}
		}
	}
}

func TestGetFlag(t *testing.T) {
	registry := mustLoadEmbedded(t)
	find, ok := registry["find"]
	if !ok {
		t.Fatal(`missing "find" manifest`)
	}

	if got := find.GetFlag("-name"); got == nil {
		t.Fatal("find.GetFlag(-name) = nil")
	}
	if got := find.GetFlag("--definitely-missing"); got != nil {
		t.Fatal("find.GetFlag(missing) should be nil")
	}
}

func TestDefaultTimeoutAndStdoutAndRegexPosition(t *testing.T) {
	m, err := parseManifest(map[string]any{
		"name": "ls",
	}, "test.yaml")
	if err != nil {
		t.Fatalf("parseManifest() error = %v", err)
	}

	if got, want := m.Timeout, 30; got != want {
		t.Fatalf("Timeout = %d, want %d", got, want)
	}
	if !m.Stdout {
		t.Fatal("Stdout default should be true")
	}
	if m.RegexArgPosition != nil {
		t.Fatal("RegexArgPosition should default to nil")
	}
}

func TestRegexArgPositionZeroPreserved(t *testing.T) {
	m, err := parseManifest(map[string]any{
		"name":               "grep",
		"regex_arg_position": 0,
	}, "test.yaml")
	if err != nil {
		t.Fatalf("parseManifest() error = %v", err)
	}

	if m.RegexArgPosition == nil {
		t.Fatal("RegexArgPosition should not be nil")
	}
	if got, want := *m.RegexArgPosition, 0; got != want {
		t.Fatalf("*RegexArgPosition = %d, want %d", got, want)
	}
}

func TestKeyFlagsExist(t *testing.T) {
	registry := mustLoadEmbedded(t)

	keyFlags := map[string][]string{
		"grep":       {"-C", "-A", "-B", "-i", "-r", "-v", "-c", "-l", "-n", "-E", "-P", "-h", "-w"},
		"ls":         {"-l", "-a", "-h", "-t", "-R", "-1"},
		"find":       {"-name", "-type", "-mtime", "-size", "-maxdepth", "-path", "-iname", "-o", "-print0"},
		"psql":       {"-c", "-t", "-d", "-p", "-U", "-A", "-F", "-x"},
		"tail":       {"-f", "--follow"},
		"journalctl": {"-f", "--follow"},
		"curl":       {"-X", "--request", "-d", "--data", "--data-binary", "--data-urlencode", "-o", "--output", "-O", "--remote-name", "-T", "--upload-file"},
	}

	for command, flags := range keyFlags {
		m, ok := registry[command]
		if !ok {
			t.Fatalf("missing manifest %q", command)
		}
		for _, f := range flags {
			if m.GetFlag(f) == nil {
				t.Fatalf("%s missing flag %s", command, f)
			}
		}
	}
}

func TestDestructiveSubcommandsAbsent(t *testing.T) {
	registry := mustLoadEmbedded(t)

	absent := []string{
		"docker_run", "docker_exec", "docker_rm", "docker_stop", "docker_kill", "docker_start",
		"docker_build", "docker_pull", "docker_push", "docker_cp",
		"kubectl_exec", "kubectl_apply", "kubectl_delete", "kubectl_edit", "kubectl_patch", "kubectl_create", "kubectl_run", "kubectl_cp",
		"systemctl_start", "systemctl_stop", "systemctl_restart", "systemctl_enable", "systemctl_disable", "systemctl_reload", "systemctl_daemon-reload", "systemctl_mask",
	}

	for _, name := range absent {
		if _, ok := registry[name]; ok {
			t.Fatalf("destructive subcommand %q should not exist in manifests", name)
		}
	}
}

func TestPowerShellDiagnosticManifests(t *testing.T) {
	registry := mustLoadEmbedded(t)

	// Key new cmdlets from the 2026-04-20 PowerShell parser expansion.
	// Spot-check that they loaded with the expected shape.
	cases := []struct {
		name  string
		flags []string
	}{
		{"get-ciminstance", []string{"-ClassName", "-Query", "-Filter", "-MethodName"}},
		{"foreach-object", []string{"-MemberName"}},
		{"group-object", []string{"-Property", "-NoElement"}},
		{"test-netconnection", []string{"-ComputerName", "-Port"}},
		{"get-netfirewallrule", []string{"-DisplayName", "-Enabled"}},
		{"resolve-dnsname", []string{"-Name", "-Type"}},
		{"get-scheduledtask", []string{"-TaskName"}},
		{"get-localuser", []string{"-Name"}},
		{"get-help", []string{"-Name", "-Examples"}},
		{"get-command", []string{"-Name", "-Module"}},
		{"get-member", []string{"-MemberType", "-Static"}},
		{"convertfrom-json", []string{"-Depth", "-AsHashtable"}},
		{"convertfrom-csv", []string{"-Delimiter", "-Header"}},
		{"get-netipconfiguration", []string{"-InterfaceIndex", "-Detailed"}},
		{"get-dnsclientserveraddress", []string{"-InterfaceIndex", "-AddressFamily"}},
		{"get-uptime", []string{"-Since"}},
		{"get-filehash", []string{"-Algorithm", "-LiteralPath"}},
		{"get-timezone", []string{"-ListAvailable"}},
		// Flag coverage additions
		{"get-content", []string{"-Raw", "-Encoding"}},
		{"select-string", []string{"-Context", "-AllMatches", "-Quiet", "-Encoding"}},
		{"get-childitem", []string{"-Force", "-File", "-Directory", "-Depth"}},
		{"get-process", []string{"-IncludeUserName", "-Module"}},
		{"get-winevent", []string{"-ProviderName", "-FilterXPath"}},
		{"select-object", []string{"-Unique", "-Skip", "-Index"}},
		{"sort-object", []string{"-Unique", "-Top", "-Bottom"}},
		// SIMULIA / 3DEXPERIENCE diagnostic additions (2026-04-22)
		{"select-xml", []string{"-XPath", "-Path", "-Namespace"}},
		{"get-netfirewallprofile", []string{"-Name", "-All"}},
		{"get-netipinterface", []string{"-InterfaceIndex", "-AddressFamily", "-Forwarding"}},
		{"get-netconnectionprofile", []string{"-Name", "-InterfaceAlias", "-NetworkCategory"}},
		{"get-netadapterstatistics", []string{"-Name", "-InterfaceDescription"}},
		{"convertfrom-stringdata", []string{"-StringData", "-Delimiter"}},
		// HTTP healthcheck cmdlets (restricted allow, GET/HEAD only)
		{"invoke-webrequest", []string{"-Uri", "-Method", "-UseBasicParsing", "-TimeoutSec"}},
		{"invoke-restmethod", []string{"-Uri", "-Method", "-UseBasicParsing", "-TimeoutSec"}},
	}
	for _, tc := range cases {
		m, ok := registry[tc.name]
		if !ok {
			t.Errorf("missing manifest %q", tc.name)
			continue
		}
		if m.Shell != "powershell" {
			t.Errorf("%s: Shell = %q, want powershell", tc.name, m.Shell)
		}
		for _, f := range tc.flags {
			if m.GetFlag(f) == nil {
				t.Errorf("%s: missing flag %s", tc.name, f)
			}
		}
	}

	// Get-CimInstance's -MethodName must be explicitly denied.
	cim := registry["get-ciminstance"]
	if cim != nil {
		mn := cim.GetFlag("-MethodName")
		if mn == nil {
			t.Fatal("get-ciminstance missing -MethodName flag")
		}
		if !mn.Deny {
			t.Error("get-ciminstance: -MethodName should be denied (write-capable)")
		}
		if mn.Reason == "" {
			t.Error("get-ciminstance: -MethodName deny must have a reason")
		}
	}

	// Get-WmiObject is deprecated; deny reason should steer to Get-CimInstance.
	wmi, ok := registry["get-wmiobject"]
	if !ok {
		t.Fatal("missing denied manifest get-wmiobject")
	}
	if !wmi.Deny {
		t.Error("get-wmiobject should be denied")
	}
	if !strings.Contains(wmi.Reason, "Get-CimInstance") {
		t.Errorf("get-wmiobject reason should mention Get-CimInstance, got %q", wmi.Reason)
	}

	// Invoke-WebRequest / Invoke-RestMethod are allowed for healthchecks, but
	// write-capable / credential / bypass flags must be explicitly denied to
	// match the read-only diagnostic policy (mirrors curl's GET-only pattern).
	httpMustDeny := []string{
		"-Body", "-InFile", "-Form", "-OutFile",
		"-Credential", "-UseDefaultCredentials", "-CertificateThumbprint", "-Certificate",
		"-Proxy", "-ProxyCredential", "-ProxyUseDefaultCredentials",
		"-SkipCertificateCheck", "-AllowInsecureRedirect", "-AllowUnencryptedAuthentication",
		"-SessionVariable", "-WebSession", "-CustomMethod", "-Headers",
	}
	for _, cmdlet := range []string{"invoke-webrequest", "invoke-restmethod"} {
		m, ok := registry[cmdlet]
		if !ok {
			t.Errorf("missing manifest %q", cmdlet)
			continue
		}
		if m.Deny {
			t.Errorf("%s should be allowed (restricted), not denied", cmdlet)
		}
		for _, flagName := range httpMustDeny {
			f := m.GetFlag(flagName)
			if f == nil {
				t.Errorf("%s: missing entry for %s (must be explicitly denied)", cmdlet, flagName)
				continue
			}
			if !f.Deny {
				t.Errorf("%s: %s must be denied", cmdlet, flagName)
			}
			if f.Reason == "" {
				t.Errorf("%s: %s deny must have a reason", cmdlet, flagName)
			}
		}
		// -Method must be restricted to GET/HEAD.
		method := m.GetFlag("-Method")
		if method == nil {
			t.Errorf("%s: missing -Method flag", cmdlet)
			continue
		}
		if len(method.AllowedValues) == 0 {
			t.Errorf("%s: -Method must have allowed_values", cmdlet)
		}
		for _, v := range method.AllowedValues {
			if !strings.EqualFold(v, "GET") && !strings.EqualFold(v, "HEAD") {
				t.Errorf("%s: -Method allowed_values should only contain GET/HEAD, got %q", cmdlet, v)
			}
		}
	}
}

func TestLoadFromFS_DuplicateNameErrors(t *testing.T) {
	fsys := fstest.MapFS{
		"foo.yaml": &fstest.MapFile{Data: []byte("name: duplicate\ndescription: first\nflags: []\n")},
		"bar.yaml": &fstest.MapFile{Data: []byte("name: duplicate\ndescription: second\nflags: []\n")},
	}
	_, err := loadFromFS(fsys, ".")
	if err == nil {
		t.Fatal("loadFromFS() expected error for duplicate manifest name, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("error = %q, want mention of duplicate name", err.Error())
	}
	var me *ManifestError
	if !errors.As(err, &me) {
		t.Fatalf("error type = %T, want *ManifestError", err)
	}
}
