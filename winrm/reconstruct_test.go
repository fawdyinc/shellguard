package winrm

import (
	"strings"
	"testing"

	"github.com/fawdyinc/shellguard/parser"
)

func TestPowerShellQuote(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "''"},
		{"hello", "hello"},
		{"hello world", "'hello world'"},
		{"-Name", "-Name"},
		{"@{LogName='System'}", "@{LogName='System'}"},
		{"can't", "'can''t'"},
		{"C:\\logs\\app.log", "C:\\logs\\app.log"},
		{"*.log", "*.log"},
		{"simple", "simple"},
		{"with space", "'with space'"},
		{"it's", "'it''s'"},
		{"$env:USERNAME", "$env:USERNAME"},
		{"$env:PATH", "$env:PATH"},
		{"$env:UNKNOWN_VAR", "$env:UNKNOWN_VAR"},
		// $-prefixed but not an env ref — treat as string, quote it.
		{"$foo", "'$foo'"},
		{"$env:", "'$env:'"},
	}

	for _, tc := range tests {
		got := PowerShellQuote(tc.input)
		if got != tc.want {
			t.Errorf("PowerShellQuote(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestReconstructPowerShellCommand(t *testing.T) {
	tests := []struct {
		name     string
		pipeline *parser.Pipeline
		want     string
	}{
		{
			name: "simple cmdlet",
			pipeline: &parser.Pipeline{Segments: []parser.PipelineSegment{
				{Command: "get-process"},
			}},
			want: "get-process",
		},
		{
			name: "cmdlet with flag and value",
			pipeline: &parser.Pipeline{Segments: []parser.PipelineSegment{
				{Command: "get-process", Args: []string{"-Name", "svchost"}},
			}},
			want: "get-process -Name svchost",
		},
		{
			name: "pipeline",
			pipeline: &parser.Pipeline{Segments: []parser.PipelineSegment{
				{Command: "get-process", Args: []string{"-Name", "svc"}},
				{Command: "select-object", Args: []string{"Id,Name"}, Operator: "|"},
			}},
			want: "get-process -Name svc | select-object Id,Name",
		},
		{
			name: "value with spaces",
			pipeline: &parser.Pipeline{Segments: []parser.PipelineSegment{
				{Command: "get-content", Args: []string{"-Path", "C:\\Program Files\\app.log"}},
			}},
			want: "get-content -Path 'C:\\Program Files\\app.log'",
		},
		{
			name: "hashtable passthrough",
			pipeline: &parser.Pipeline{Segments: []parser.PipelineSegment{
				{Command: "get-winevent", Args: []string{"-FilterHashtable", "@{LogName='System'; Level='2'}"}},
			}},
			want: "get-winevent -FilterHashtable @{LogName='System'; Level='2'}",
		},
		{
			name:     "nil pipeline",
			pipeline: nil,
			want:     "",
		},
		{
			name:     "empty pipeline",
			pipeline: &parser.Pipeline{},
			want:     "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ReconstructPowerShellCommand(tc.pipeline)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWrapForWinRM(t *testing.T) {
	wrapped := WrapForWinRM("Get-Process")

	if !strings.HasPrefix(wrapped, "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ") {
		t.Errorf("unexpected prefix: %s", wrapped)
	}

	// The encoded part should be valid base64
	parts := strings.SplitN(wrapped, "-EncodedCommand ", 2)
	if len(parts) != 2 {
		t.Fatal("expected -EncodedCommand in output")
	}
	if parts[1] == "" {
		t.Error("encoded command is empty")
	}
}

func TestEncodeUTF16LEBase64(t *testing.T) {
	// "AB" → UTF-16LE: 0x41 0x00 0x42 0x00 → base64: "QQBCAA=="
	got := encodeUTF16LEBase64("AB")
	if got != "QQBCAA==" {
		t.Errorf("encodeUTF16LEBase64(\"AB\") = %q, want \"QQBCAA==\"", got)
	}
}

func TestReconstructPowerShellCommand_QuoteEscaping(t *testing.T) {
	pipeline := &parser.Pipeline{Segments: []parser.PipelineSegment{
		{Command: "get-content", Args: []string{"-Path", "it's a file"}},
	}}
	got := ReconstructPowerShellCommand(pipeline)
	if !strings.Contains(got, "'it''s a file'") {
		t.Errorf("expected escaped single quotes, got %q", got)
	}
}

// Regression: a Select-Object -Property list mixing identifiers with a
// calculated property must not be quoted as one token. Quoting the joined
// list turns it into a single string property name, which PowerShell resolves
// to a literal-named empty column (2026-08-20 windows-dev audit, row 8).
func TestReconstructPowerShellCommand_CommaListWithHashtable(t *testing.T) {
	cmd := `Get-Process | Sort-Object -Property WorkingSet64 -Descending | Select-Object -First 5 -Property Name, Id, @{N='MB';E={[math]::Round($_.WorkingSet64/1MB,1)}}`
	pipeline, err := parser.ParsePowerShell(cmd)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := ReconstructPowerShellCommand(pipeline)
	if strings.Contains(got, "'Name") {
		t.Errorf("property list was quoted as a single string: %q", got)
	}
	if !strings.Contains(got, "Name,Id,@{") {
		t.Errorf("expected unquoted property array, got %q", got)
	}
}

func TestPowerShellQuote_CommaLists(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Mixed list with hashtable: per-element quoting, hashtable verbatim.
		{"Name,Id,@{N='MB'; E={[math]::Round($_.WorkingSet64/1MB,1)}}",
			"Name,Id,@{N='MB'; E={[math]::Round($_.WorkingSet64/1MB,1)}}"},
		// Commas inside the hashtable are not split points.
		{"Name,@{N='a,b'; E={[math]::Round($_.CPU,2)}}",
			"Name,@{N='a,b'; E={[math]::Round($_.CPU,2)}}"},
		// Plain identifier lists keep existing pass-through behavior.
		{"Name,Id", "Name,Id"},
		// A string arg containing commas (no hashtable) keeps whole-token quoting.
		{"foo, bar", "'foo, bar'"},
	}
	for _, tc := range tests {
		if got := PowerShellQuote(tc.input); got != tc.want {
			t.Errorf("PowerShellQuote(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// PowerShell 5.1 shadows `curl` with an Invoke-WebRequest alias whose flags
// are incompatible with real curl — the 2026-08-20 customer-demo failure.
// Validated curl pipelines must execute as curl.exe.
func TestReconstructPowerShellCommand_CurlAliasBypass(t *testing.T) {
	pipeline, err := parser.ParsePowerShell("curl -sS -k -m 10 -I 'https://example.com'")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := ReconstructPowerShellCommand(pipeline)
	if !strings.HasPrefix(got, "curl.exe ") {
		t.Errorf("expected curl to be rewritten to curl.exe, got %q", got)
	}
}
