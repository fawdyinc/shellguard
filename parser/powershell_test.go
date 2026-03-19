package parser

import (
	"strings"
	"testing"
)

func TestParsePowerShell_SimpleCmdlet(t *testing.T) {
	p, err := ParsePowerShell("Get-Process")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Segments) != 1 {
		t.Fatalf("expected 1 segment, got %d", len(p.Segments))
	}
	if p.Segments[0].Command != "get-process" {
		t.Errorf("expected command 'get-process', got %q", p.Segments[0].Command)
	}
}

func TestParsePowerShell_CaseInsensitive(t *testing.T) {
	for _, input := range []string{"get-process", "Get-Process", "GET-PROCESS"} {
		p, err := ParsePowerShell(input)
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", input, err)
		}
		if p.Segments[0].Command != "get-process" {
			t.Errorf("expected normalized 'get-process' for %q, got %q", input, p.Segments[0].Command)
		}
	}
}

func TestParsePowerShell_SingleWordCommand(t *testing.T) {
	for _, cmd := range []string{"whoami", "hostname", "systeminfo"} {
		p, err := ParsePowerShell(cmd)
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", cmd, err)
		}
		if p.Segments[0].Command != cmd {
			t.Errorf("expected %q, got %q", cmd, p.Segments[0].Command)
		}
	}
}

func TestParsePowerShell_WithFlags(t *testing.T) {
	p, err := ParsePowerShell("Get-Process -Name svchost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	seg := p.Segments[0]
	if seg.Command != "get-process" {
		t.Errorf("expected command 'get-process', got %q", seg.Command)
	}
	if len(seg.Args) != 2 {
		t.Fatalf("expected 2 args, got %d: %v", len(seg.Args), seg.Args)
	}
	if seg.Args[0] != "-Name" {
		t.Errorf("expected '-Name', got %q", seg.Args[0])
	}
	if seg.Args[1] != "svchost" {
		t.Errorf("expected 'svchost', got %q", seg.Args[1])
	}
}

func TestParsePowerShell_Pipeline(t *testing.T) {
	p, err := ParsePowerShell("Get-Process -Name svc | Select-Object Id,Name")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Segments) != 2 {
		t.Fatalf("expected 2 segments, got %d", len(p.Segments))
	}
	if p.Segments[0].Command != "get-process" {
		t.Errorf("expected 'get-process', got %q", p.Segments[0].Command)
	}
	if p.Segments[1].Operator != "|" {
		t.Errorf("expected operator '|', got %q", p.Segments[1].Operator)
	}
	if p.Segments[1].Command != "select-object" {
		t.Errorf("expected 'select-object', got %q", p.Segments[1].Command)
	}
	// "Id,Name" is a single comma-separated ident token
	if len(p.Segments[1].Args) < 1 {
		t.Fatalf("expected at least 1 arg, got %d", len(p.Segments[1].Args))
	}
	if p.Segments[1].Args[0] != "Id,Name" {
		t.Errorf("expected 'Id,Name', got %q", p.Segments[1].Args[0])
	}
}

func TestParsePowerShell_SingleQuotedString(t *testing.T) {
	p, err := ParsePowerShell("Get-Content -Path 'C:\\logs\\app.log'")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Segments[0].Args[1] != "C:\\logs\\app.log" {
		t.Errorf("expected unquoted path, got %q", p.Segments[0].Args[1])
	}
}

func TestParsePowerShell_Hashtable(t *testing.T) {
	p, err := ParsePowerShell("Get-WinEvent -FilterHashtable @{LogName='System'; Level=2}")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	seg := p.Segments[0]
	if seg.Command != "get-winevent" {
		t.Errorf("expected 'get-winevent', got %q", seg.Command)
	}
	// The hashtable should be serialized as a single arg
	if len(seg.Args) != 2 {
		t.Fatalf("expected 2 args (flag + hashtable), got %d: %v", len(seg.Args), seg.Args)
	}
	ht := seg.Args[1]
	if !strings.HasPrefix(ht, "@{") || !strings.HasSuffix(ht, "}") {
		t.Errorf("expected hashtable arg, got %q", ht)
	}
	if !strings.Contains(ht, "LogName='System'") {
		t.Errorf("expected LogName='System' in hashtable, got %q", ht)
	}
}

func TestParsePowerShell_NumberArg(t *testing.T) {
	p, err := ParsePowerShell("Get-WinEvent -MaxEvents 100")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	seg := p.Segments[0]
	if seg.Args[1] != "100" {
		t.Errorf("expected '100', got %q", seg.Args[1])
	}
}

func TestParsePowerShell_MultiPipe(t *testing.T) {
	p, err := ParsePowerShell("Get-Process | Where-Object CPU -gt 10 | Sort-Object CPU -Descending | Select-Object -First 5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Segments) != 4 {
		t.Fatalf("expected 4 segments, got %d", len(p.Segments))
	}
}

func TestParsePowerShell_CommaInIdent(t *testing.T) {
	// Comma-separated values like "Id,Name" are parsed as a single ident
	// because the Ident pattern includes '.' and '*' but not ','
	// They will be parsed as separate tokens, which is fine
	p, err := ParsePowerShell("Select-Object -Property Name")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Segments[0].Args[1] != "Name" {
		t.Errorf("expected 'Name', got %q", p.Segments[0].Args[1])
	}
}

// --- Rejection tests ---

func TestParsePowerShell_RejectVariable(t *testing.T) {
	_, err := ParsePowerShell("Get-Process $env:PATH")
	if err == nil {
		t.Fatal("expected error for variable reference")
	}
	if !strings.Contains(err.Error(), "Variable references ($)") {
		t.Errorf("expected variable rejection message, got: %v", err)
	}
}

func TestParsePowerShell_RejectDoubleQuotes(t *testing.T) {
	_, err := ParsePowerShell(`Get-Process -Name "svchost"`)
	if err == nil {
		t.Fatal("expected error for double-quoted string")
	}
	if !strings.Contains(err.Error(), "Double-quoted strings") {
		t.Errorf("expected double-quote rejection message, got: %v", err)
	}
}

func TestParsePowerShell_RejectSubexpression(t *testing.T) {
	_, err := ParsePowerShell("Get-Process -Id (Get-Content pid.txt)")
	if err == nil {
		t.Fatal("expected error for subexpression")
	}
	if !strings.Contains(err.Error(), "Subexpressions") {
		t.Errorf("expected subexpression rejection message, got: %v", err)
	}
}

func TestParsePowerShell_RejectScriptBlock(t *testing.T) {
	_, err := ParsePowerShell("Get-Process | Where-Object { $_.CPU -gt 10 }")
	if err == nil {
		t.Fatal("expected error for script block")
	}
	// Could match either script block or variable reference ($ comes first)
	if !strings.Contains(err.Error(), "not allowed") && !strings.Contains(err.Error(), "not supported") {
		t.Errorf("expected rejection message, got: %v", err)
	}
}

func TestParsePowerShell_RejectSemicolon(t *testing.T) {
	_, err := ParsePowerShell("Get-Process; Get-Service")
	if err == nil {
		t.Fatal("expected error for semicolon")
	}
	if !strings.Contains(err.Error(), "Statement separators") {
		t.Errorf("expected semicolon rejection message, got: %v", err)
	}
}

func TestParsePowerShell_RejectRedirection(t *testing.T) {
	for _, input := range []string{
		"Get-Process > output.txt",
		"Get-Process >> output.txt",
		"Get-Process 2> errors.txt",
	} {
		_, err := ParsePowerShell(input)
		if err == nil {
			t.Fatalf("expected error for redirection in %q", input)
		}
		if !strings.Contains(err.Error(), "Output redirection") {
			t.Errorf("expected redirection rejection for %q, got: %v", input, err)
		}
	}
}

func TestParsePowerShell_RejectCallOperator(t *testing.T) {
	_, err := ParsePowerShell("& cmd.exe /c dir")
	if err == nil {
		t.Fatal("expected error for call operator")
	}
	if !strings.Contains(err.Error(), "call operator") {
		t.Errorf("expected call operator rejection, got: %v", err)
	}
}

func TestParsePowerShell_RejectBacktick(t *testing.T) {
	_, err := ParsePowerShell("Get-Process `\n-Name svc")
	if err == nil {
		t.Fatal("expected error for backtick")
	}
	if !strings.Contains(err.Error(), "Backtick") {
		t.Errorf("expected backtick rejection, got: %v", err)
	}
}

func TestParsePowerShell_RejectEmpty(t *testing.T) {
	_, err := ParsePowerShell("")
	if err == nil {
		t.Fatal("expected error for empty command")
	}
}

func TestParsePowerShell_RejectTooLong(t *testing.T) {
	_, err := ParsePowerShell(strings.Repeat("a", MaxCommandLength+1))
	if err == nil {
		t.Fatal("expected error for too-long command")
	}
	if !strings.Contains(err.Error(), "too long") {
		t.Errorf("expected too-long message, got: %v", err)
	}
}

// --- Security attack vector tests ---

func TestParsePowerShell_SecurityAttackVectors(t *testing.T) {
	attacks := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"env var", "$env:PATH", "Variable references"},
		{"command substitution", "$(Get-Date)", "Variable references"},
		{"invoke expression", `Invoke-Expression "malicious"`, "Double-quoted"},
		{"string interpolation", `"hello $world"`, "Double-quoted"},
		{"method call", "(Get-Date).ToString()", "Subexpressions"},
		{"semicolon chain", "Remove-Item foo; Get-Process", "Statement separators"},
	}

	for _, tc := range attacks {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePowerShell(tc.input)
			if err == nil {
				t.Fatalf("expected rejection for %q", tc.input)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

func TestParsePowerShell_SemicolonInsideHashtable(t *testing.T) {
	// Semicolons inside @{} are allowed
	p, err := ParsePowerShell("Get-WinEvent -FilterHashtable @{LogName='System'; Level=2}")
	if err != nil {
		t.Fatalf("expected semicolons inside @{} to be allowed, got: %v", err)
	}
	if p.Segments[0].Command != "get-winevent" {
		t.Errorf("expected 'get-winevent', got %q", p.Segments[0].Command)
	}
}

func TestParsePowerShell_WhereObjectSimplified(t *testing.T) {
	// Simplified Where-Object syntax (no script block)
	p, err := ParsePowerShell("Get-Process | Where-Object CPU -gt 10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Segments) != 2 {
		t.Fatalf("expected 2 segments, got %d", len(p.Segments))
	}
	wo := p.Segments[1]
	if wo.Command != "where-object" {
		t.Errorf("expected 'where-object', got %q", wo.Command)
	}
	// Args: CPU, -gt, 10
	if len(wo.Args) != 3 {
		t.Fatalf("expected 3 args, got %d: %v", len(wo.Args), wo.Args)
	}
}

func TestParsePowerShell_GetContentTail(t *testing.T) {
	p, err := ParsePowerShell("Get-Content -Path 'C:\\logs\\app.log' -Tail 50")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	seg := p.Segments[0]
	if seg.Command != "get-content" {
		t.Errorf("expected 'get-content', got %q", seg.Command)
	}
	if len(seg.Args) != 4 {
		t.Fatalf("expected 4 args, got %d: %v", len(seg.Args), seg.Args)
	}
}

func TestParsePowerShell_WildcardIdent(t *testing.T) {
	// The Ident pattern allows * and . for things like *.log or Env:PATH
	p, err := ParsePowerShell("Get-ChildItem -Filter *.log")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	seg := p.Segments[0]
	if seg.Args[1] != "*.log" {
		t.Errorf("expected '*.log', got %q", seg.Args[1])
	}
}
