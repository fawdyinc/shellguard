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
