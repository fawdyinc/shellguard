// Package winrm provides PowerShell command reconstruction and WinRM transport.
package winrm

import (
	"encoding/base64"
	"strings"
	"unicode/utf16"

	"github.com/fawdyinc/shellguard/parser"
)

// PowerShellQuote single-quotes a token for safe use in PowerShell.
// Embedded single quotes are escaped by doubling (”).
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
	// Comma-lists that mix identifiers with hashtable literals (e.g.
	// `Name,Id,@{N='MB';E={...}}` from Select-Object -Property) must be
	// quoted per element: quoting the joined token turns the whole list
	// into a single string property name, which PowerShell resolves to an
	// empty column instead of an array of properties.
	if parts, ok := splitTopLevelCommaList(token); ok {
		quoted := make([]string, len(parts))
		for i, p := range parts {
			quoted[i] = PowerShellQuote(p)
		}
		return strings.Join(quoted, ",")
	}
	// Env refs pass through unquoted so PowerShell resolves the variable at
	// execution time. The parser's EnvRef token already validated the shape.
	if isPSEnvRef(token) {
		return token
	}
	// Identifiers that are safe don't need quoting.
	if isPSSafeToken(token) {
		return token
	}
	// Single-quote with embedded quote doubling.
	return "'" + strings.ReplaceAll(token, "'", "''") + "'"
}

// splitTopLevelCommaList splits token at commas that sit outside any brace
// nesting and outside single quotes. It reports ok only when the token is a
// genuine mixed comma-list — at least one top-level comma AND at least one
// element that is a hashtable literal. Plain identifier lists (`Name,Id`) and
// string arguments that merely contain commas keep their existing quoting.
func splitTopLevelCommaList(token string) ([]string, bool) {
	var parts []string
	depth := 0
	inQuote := false
	start := 0
	for i, r := range token {
		switch {
		case r == '\'':
			inQuote = !inQuote
		case inQuote:
		case r == '{':
			depth++
		case r == '}':
			if depth > 0 {
				depth--
			}
		case r == ',' && depth == 0:
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	if len(parts) < 2 {
		return nil, false
	}
	hasHashtable := false
	for _, p := range parts {
		if strings.HasPrefix(p, "@{") {
			hasHashtable = true
			break
		}
	}
	return parts, hasHashtable
}

// isPSEnvRef returns true if the token matches the parser's EnvRef shape:
// $env: followed by a legal identifier. Case-insensitive "env".
func isPSEnvRef(token string) bool {
	if len(token) < 6 || token[0] != '$' {
		return false
	}
	e, n, v, colon := token[1], token[2], token[3], token[4]
	if (e != 'e' && e != 'E') || (n != 'n' && n != 'N') || (v != 'v' && v != 'V') || colon != ':' {
		return false
	}
	rest := token[5:]
	if len(rest) == 0 {
		return false
	}
	for i, r := range rest {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_'
		if i > 0 {
			ok = ok || (r >= '0' && r <= '9')
		}
		if !ok {
			return false
		}
	}
	return true
}

// psAliasBypass maps command names that PowerShell 5.1 shadows with cmdlet
// aliases to their explicit .exe spellings. A validated `curl -k -m 10 <url>`
// otherwise resolves to the Invoke-WebRequest alias, which is a denied cmdlet
// with incompatible flags — the validated command is not the command that runs.
// curl.exe ships in System32 on Windows Server 2016+/Windows 10 1803+.
var psAliasBypass = map[string]string{
	"curl": "curl.exe",
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
		name := seg.Command
		if exe, ok := psAliasBypass[name]; ok {
			name = exe
		}
		tokens := make([]string, 0, len(seg.Args)+1)
		tokens = append(tokens, name) // command name unquoted
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
