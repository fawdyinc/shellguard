// Package winrm provides PowerShell command reconstruction and WinRM transport.
package winrm

import (
	"encoding/base64"
	"strings"
	"unicode/utf16"

	"github.com/fawdyinc/shellguard/parser"
)

// PowerShellQuote single-quotes a token for safe use in PowerShell.
// Embedded single quotes are escaped by doubling ('').
// Flags (starting with -) and pipeline operators pass through unquoted.
func PowerShellQuote(token string) string {
	if token == "" {
		return "''"
	}
	// Flags pass through unquoted (already validated as identifiers).
	if strings.HasPrefix(token, "-") {
		return token
	}
	// Hashtable literals pass through as-is (already safe from parser).
	if strings.HasPrefix(token, "@{") {
		return token
	}
	// Identifiers that are safe don't need quoting.
	if isPSSafeToken(token) {
		return token
	}
	// Single-quote with embedded quote doubling.
	return "'" + strings.ReplaceAll(token, "'", "''") + "'"
}

// ReconstructPowerShellCommand rebuilds a validated pipeline into a PowerShell
// command string with proper quoting.
func ReconstructPowerShellCommand(pipeline *parser.Pipeline) string {
	if pipeline == nil || len(pipeline.Segments) == 0 {
		return ""
	}

	parts := make([]string, 0, len(pipeline.Segments)*2)
	for _, seg := range pipeline.Segments {
		if seg.Operator != "" {
			parts = append(parts, seg.Operator)
		}
		tokens := make([]string, 0, len(seg.Args)+1)
		tokens = append(tokens, seg.Command) // command name unquoted
		for _, arg := range seg.Args {
			tokens = append(tokens, PowerShellQuote(arg))
		}
		parts = append(parts, strings.Join(tokens, " "))
	}

	return strings.Join(parts, " ")
}

// WrapForWinRM wraps a PowerShell command string for execution over WinRM.
// WinRM's default shell is cmd.exe, so we encode the PowerShell command as
// UTF-16LE base64 and pass it via -EncodedCommand to avoid quoting issues.
func WrapForWinRM(psCommand string) string {
	encoded := encodeUTF16LEBase64(psCommand)
	return "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded
}

// encodeUTF16LEBase64 converts a string to UTF-16LE and base64 encodes it.
// This is the format PowerShell expects for -EncodedCommand.
func encodeUTF16LEBase64(s string) string {
	runes := utf16.Encode([]rune(s))
	b := make([]byte, len(runes)*2)
	for i, r := range runes {
		b[i*2] = byte(r)
		b[i*2+1] = byte(r >> 8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// isPSSafeToken returns true if the token needs no quoting in PowerShell.
func isPSSafeToken(token string) bool {
	for _, r := range token {
		if (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '_' || r == '.' || r == '-' || r == ':' || r == '\\' || r == '/' || r == '*' || r == ',' {
			continue
		}
		return false
	}
	return true
}
