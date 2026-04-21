package parser

import (
	"testing"
)

// FuzzParsePowerShell asserts two safety invariants for arbitrary input:
//
//  1. The parser must not panic.
//  2. Any accepted parse must produce command names made of characters
//     the grammar's Ident lexer token admits (letters, digits, underscore,
//     hyphen, dot, colon, wildcard, comma, backslash). Argument *values*
//     are not constrained — single-quoted string contents can legitimately
//     contain anything — but the command name itself is emitted unquoted
//     by the reconstructor, so an unsafe cmdlet name is an injection
//     surface.
//
// When the grammar expands to accept more productions (Workstream C), this
// fuzz target remains valid: new productions produce new valid Command /
// Args, not new unsafe ones.
func FuzzParsePowerShell(f *testing.F) {
	seeds := []string{
		"Get-Process",
		"Get-Process | Where-Object CPU -gt 10",
		"Get-Content -Path 'C:\\logs\\app.log'",
		"Get-WinEvent -FilterHashtable @{LogName='System'; Level=2}",
		"Get-ChildItem -Filter *.log",
		"Select-Object -Property Name",
		"",
		"$env:PATH",
		`"interpolated $var"`,
		"& cmd.exe",
		"Get-Process; Get-Service",
		"Get-Process > output.txt",
		"Get-Process | Where-Object { $_.CPU -gt 10 }",
		"(Get-Date).ToString()",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		p, err := ParsePowerShell(input)
		if err != nil {
			return
		}
		if p == nil {
			t.Fatalf("nil pipeline with no error for input %q", input)
		}
		for _, seg := range p.Segments {
			if seg.Command == "" {
				t.Errorf("empty command in accepted parse for input %q", input)
			}
			if !isSafeCmdName(seg.Command) {
				t.Errorf("unsafe char in accepted command %q (input: %q)", seg.Command, input)
			}
		}
	})
}

// isSafeCmdName returns true if name contains only characters the Ident
// lexer token admits. See psLexer in powershell.go.
func isSafeCmdName(name string) bool {
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.' || r == ':' || r == '*' || r == ',' || r == '\\':
		default:
			return false
		}
	}
	return true
}
