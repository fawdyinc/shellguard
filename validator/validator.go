// Package validator checks parsed pipelines against the manifest registry.
package validator

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/fawdyinc/shellguard/manifest"
	"github.com/fawdyinc/shellguard/parser"
)

var (
	sqlAllowedPrefixes = []string{"SELECT", "EXPLAIN", "SHOW", "WITH", "\\d", "\\l", "\\dt", "\\di", "\\dn", "\\du", "\\df", "\\x", "\\timing", "\\pset"}
	globChars          = regexp.MustCompile(`[*?\[]`)
)

// psCommonParams are PowerShell common parameters allowed globally for all
// PowerShell cmdlets. These are checked before manifest flag validation.
// See: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_commonparameters
var psCommonParams = map[string]bool{
	"-ErrorAction":        true,
	"-ErrorVariable":      true,
	"-WarningAction":      true,
	"-WarningVariable":    true,
	"-InformationAction":  true,
	"-InformationVariable": true,
	"-OutVariable":        true,
	"-OutBuffer":          true,
	"-PipelineVariable":   true,
	"-Verbose":            true,
	"-Debug":              true,
	"-ProgressAction":     true,
}

// psCommonParamsTakesValue indicates which common params expect a value.
var psCommonParamsTakesValue = map[string]bool{
	"-ErrorAction":        true,
	"-ErrorVariable":      true,
	"-WarningAction":      true,
	"-WarningVariable":    true,
	"-InformationAction":  true,
	"-InformationVariable": true,
	"-OutVariable":        true,
	"-OutBuffer":          true,
	"-PipelineVariable":   true,
	"-ProgressAction":     true,
}

type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

func ValidatePipeline(pipeline *parser.Pipeline, registry map[string]*manifest.Manifest) error {
	for i, seg := range pipeline.Segments {
		if err := validateSegment(seg, registry, i == 0); err != nil {
			return err
		}
	}
	return nil
}

func validateSegment(segment parser.PipelineSegment, registry map[string]*manifest.Manifest, _ bool) error {
	command := segment.Command
	args := append([]string(nil), segment.Args...)

	if command == "sudo" {
		return validateSudo(segment, registry)
	}

	if command == "xargs" {
		return validateXargs(segment, registry)
	}

	if manifest.SubcommandCommands[command] {
		return validateSubcommandCommand(command, args, registry)
	}

	m := registry[command]
	if m == nil {
		if closest := closestCmdlet(command, registry); closest != "" {
			return &ValidationError{Message: fmt.Sprintf("Command '%s' is not available. Did you mean '%s'?", command, closest)}
		}
		return &ValidationError{Message: fmt.Sprintf("Command '%s' is not available.", command)}
	}
	if m.Deny {
		return &ValidationError{Message: fmt.Sprintf("Command '%s' is not available: %s", command, m.Reason)}
	}

	return validateArgs(command, args, m)
}

// closestCmdlet returns the registry cmdlet name closest to command by
// Levenshtein distance, up to a small threshold. Returns "" when no allowed
// cmdlet is close enough — short commands would otherwise match too much.
func closestCmdlet(command string, registry map[string]*manifest.Manifest) string {
	if len(command) < 3 {
		return ""
	}
	threshold := 2
	if len(command) >= 8 {
		threshold = 3
	}
	best := ""
	bestDist := threshold + 1
	for name, m := range registry {
		if m == nil || m.Deny {
			continue
		}
		d := levenshtein(command, name)
		if d < bestDist {
			bestDist = d
			best = name
		}
	}
	if bestDist > threshold {
		return ""
	}
	return best
}

func levenshtein(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

func validateSudo(segment parser.PipelineSegment, registry map[string]*manifest.Manifest) error {
	args := segment.Args
	if len(args) == 0 {
		return &ValidationError{Message: "sudo requires a command to execute."}
	}

	// sudo -u <user> <command> [args...]
	if args[0] == "-u" {
		if len(args) < 3 {
			return &ValidationError{Message: "sudo -u requires a username and a command."}
		}
		// Reject any flag-like argument after -u <user> (e.g., sudo -u root -i).
		if strings.HasPrefix(args[2], "-") {
			return &ValidationError{Message: fmt.Sprintf("sudo flag '%s' is not supported. Only 'sudo [-u user] <command>' is allowed.", args[2])}
		}
		inner := parser.PipelineSegment{
			Command:  args[2],
			Args:     args[3:],
			Operator: segment.Operator,
		}
		return validateSegment(inner, registry, false)
	}

	// Reject any unsupported sudo flag. Only -u is handled above;
	// all other flags (-s, -i, -E, -H, --, --login, etc.) are explicitly
	// rejected rather than relying on them failing the command lookup.
	if strings.HasPrefix(args[0], "-") {
		return &ValidationError{Message: fmt.Sprintf("sudo flag '%s' is not supported. Only 'sudo [-u user] <command>' is allowed.", args[0])}
	}

	// sudo <command> [args...]
	inner := parser.PipelineSegment{
		Command:  args[0],
		Args:     args[1:],
		Operator: segment.Operator,
	}
	return validateSegment(inner, registry, false)
}

func validateXargs(segment parser.PipelineSegment, registry map[string]*manifest.Manifest) error {
	if segment.Operator != "|" {
		return &ValidationError{Message: "xargs must receive input via pipe."}
	}

	m := registry["xargs"]
	if m == nil {
		return &ValidationError{Message: "xargs manifest not found."}
	}

	args := segment.Args
	idx := 0
	for idx < len(args) {
		arg := args[idx]
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			break
		}

		if err := validateFlag("xargs", arg, m); err != nil {
			return err
		}

		flagName, _, _ := splitLongFlag(arg)
		flagObj := m.GetFlag(flagName)
		if flagObj != nil && flagObj.TakesValue {
			idx++
			if idx >= len(args) {
				return &ValidationError{Message: fmt.Sprintf("Flag '%s' requires a value.", flagName)}
			}
		}
		idx++
	}

	if idx >= len(args) {
		return &ValidationError{Message: "xargs requires a command to execute."}
	}

	wrapped := parser.PipelineSegment{Command: args[idx], Args: args[idx+1:]}
	return validateSegment(wrapped, registry, false)
}

// validateSubcommandCommand validates commands that dispatch by subcommand
// (e.g. systemctl, kubectl, defaults). It consumes any leading parent-manifest
// flags, then requires the next positional to resolve to a registered
// subcommand manifest. Without this routing, prepending a parent-allowed flag
// like `--no-pager` would skip the subcommand allowlist and let an arbitrary
// positional (`start`, `write`, `mask`) fall through to the parent's permissive
// validateArgs — defeating the read-only-only subcommand restriction.
func validateSubcommandCommand(command string, args []string, registry map[string]*manifest.Manifest) error {
	parent := registry[command]
	if parent == nil {
		return &ValidationError{Message: fmt.Sprintf("Command '%s' is not available.", command)}
	}
	if parent.Deny {
		return &ValidationError{Message: fmt.Sprintf("Command '%s' is not available: %s", command, parent.Reason)}
	}

	idx, err := consumeLeadingParentFlags(command, args, parent)
	if err != nil {
		return err
	}

	// Parent-only invocation (e.g. `kubectl --version`) — flags already validated.
	if idx >= len(args) {
		return nil
	}

	return validateSubcommand(command, args[idx:], registry)
}

// consumeLeadingParentFlags advances through args while each token is a flag
// that validates against the parent manifest. Returns the index of the first
// non-flag token (or len(args) if all tokens were flags).
func consumeLeadingParentFlags(command string, args []string, parent *manifest.Manifest) (int, error) {
	idx := 0
	for idx < len(args) {
		arg := args[idx]
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			return idx, nil
		}
		flagName, inlineValue, hasInline := splitLongFlag(arg)
		if err := validateFlag(command, flagName, parent); err != nil {
			return idx, err
		}
		flagObj := parent.GetFlag(flagName)
		if flagObj != nil && flagObj.TakesValue {
			if hasInline {
				if err := validateFlagValue(command, flagObj, inlineValue); err != nil {
					return idx, err
				}
			} else {
				idx++
				if idx >= len(args) {
					return idx, &ValidationError{Message: fmt.Sprintf("Flag '%s' requires a value.", flagName)}
				}
				if err := validateFlagValue(command, flagObj, args[idx]); err != nil {
					return idx, err
				}
			}
		}
		idx++
	}
	return idx, nil
}

func validateSubcommand(command string, args []string, registry map[string]*manifest.Manifest) error {
	if command == "aws" && len(args) >= 2 {
		k := fmt.Sprintf("%s_%s_%s", command, args[0], args[1])
		if m := registry[k]; m != nil {
			if m.Deny {
				return &ValidationError{Message: fmt.Sprintf("%s subcommand '%s %s' is not available: %s", command, args[0], args[1], m.Reason)}
			}
			return validateArgs(k, args[2:], m)
		}
	}

	sub := args[0]
	k := fmt.Sprintf("%s_%s", command, sub)
	m := registry[k]
	if m == nil {
		return &ValidationError{Message: fmt.Sprintf("%s subcommand '%s' is not available.", command, sub)}
	}
	if m.Deny {
		return &ValidationError{Message: fmt.Sprintf("%s subcommand '%s' is not available: %s", command, sub, m.Reason)}
	}
	return validateArgs(k, args[1:], m)
}

func validateArgs(command string, args []string, m *manifest.Manifest) error {
	if err := validatePsqlRequiresC(command, args); err != nil {
		return err
	}
	if err := validateUnzipRequiresMode(command, args); err != nil {
		return err
	}
	if err := validateTarExtractRequiresStdout(command, args); err != nil {
		return err
	}
	if err := validateCommandRequiresIntrospectionFlag(command, args); err != nil {
		return err
	}

	isPowerShell := m.Shell == "powershell"

	idx := 0
	positionalIdx := 0
	for idx < len(args) {
		arg := args[idx]
		if strings.HasPrefix(arg, "-") && arg != "-" {
			if isNumericCountShorthand(arg, m) {
				idx++
				continue
			}

			flagName, inlineValue, hasInline := splitLongFlag(arg)

			// Allow PowerShell common parameters globally.
			if isPowerShell && psCommonParams[flagName] {
				if psCommonParamsTakesValue[flagName] && !hasInline {
					idx++ // skip the value
				}
				idx++
				continue
			}

			if err := validateFlag(command, flagName, m); err != nil {
				return err
			}

			flagObj := m.GetFlag(flagName)
			if flagObj != nil && flagObj.TakesValue {
				if hasInline {
					if err := validateFlagValue(command, flagObj, inlineValue); err != nil {
						return err
					}
				} else {
					idx++
					if idx >= len(args) {
						return &ValidationError{Message: fmt.Sprintf("Flag '%s' requires a value.", flagName)}
					}
					if err := validateFlagValue(command, flagObj, args[idx]); err != nil {
						return err
					}
				}
			}
		} else {
			if m.AllowsPathArgs {
				if err := checkRestrictedPath(arg, m); err != nil {
					return err
				}
			}
			if m.RegexArgPosition == nil || positionalIdx != *m.RegexArgPosition {
				// Skip glob checking for PowerShell (wildcards are common in PS).
				if !isPowerShell {
					if err := checkGlobInPositional(arg); err != nil {
						return err
					}
				}
			}
			positionalIdx++
		}
		idx++
	}

	return nil
}

func splitLongFlag(arg string) (string, string, bool) {
	if strings.HasPrefix(arg, "--") {
		if eq := strings.Index(arg, "="); eq > 0 {
			return arg[:eq], arg[eq+1:], true
		}
	}
	return arg, "", false
}

func allowedFlagNames(m *manifest.Manifest) []string {
	names := make([]string, 0, len(m.Flags))
	for _, f := range m.Flags {
		if !f.Deny {
			names = append(names, f.Flag)
		}
	}
	return names
}

func allowedFlagHint(m *manifest.Manifest) string {
	names := allowedFlagNames(m)
	if len(names) == 0 {
		return ""
	}
	return " Allowed flags: " + strings.Join(names, ", ")
}

func validateFlag(command, flag string, m *manifest.Manifest) error {
	if f := m.GetFlag(flag); f != nil {
		if f.Deny {
			return &ValidationError{Message: fmt.Sprintf("Flag '%s' is not available for '%s': %s", flag, command, f.Reason) + allowedFlagHint(m)}
		}
		return nil
	}

	if len(flag) > 2 && !strings.HasPrefix(flag, "--") {
		for i := 1; i < len(flag); i++ {
			subFlag := "-" + string(flag[i])
			sub := m.GetFlag(subFlag)
			if sub == nil {
				return &ValidationError{Message: fmt.Sprintf("Flag '%s' (from '%s') is not recognized for '%s'.", subFlag, flag, command) + allowedFlagHint(m)}
			}
			if sub.Deny {
				return &ValidationError{Message: fmt.Sprintf("Flag '%s' (from '%s') is not available for '%s': %s", subFlag, flag, command, sub.Reason) + allowedFlagHint(m)}
			}
			if sub.TakesValue {
				inlineVal := flag[i+1:]
				if inlineVal != "" {
					if err := validateFlagValue(command, sub, inlineVal); err != nil {
						return err
					}
				}
				break
			}
		}
		return nil
	}

	return &ValidationError{Message: fmt.Sprintf("Flag '%s' is not recognized for '%s'.", flag, command) + allowedFlagHint(m)}
}

func validateFlagValue(command string, flag *manifest.Flag, value string) error {
	if len(flag.AllowedValues) > 0 {
		ok := false
		for _, allowed := range flag.AllowedValues {
			if value == allowed {
				ok = true
				break
			}
		}
		if !ok {
			return &ValidationError{Message: fmt.Sprintf("Value '%s' is not valid for flag '%s' of '%s'.", value, flag.Flag, command)}
		}
	}

	if command == "psql" && flag.Flag == "-c" {
		return validateSQL(value)
	}

	if !flag.PatternValue && globChars.MatchString(value) {
		return &ValidationError{Message: fmt.Sprintf("Glob pattern '%s' in flag '%s' value will not expand.", value, flag.Flag)}
	}

	return nil
}

func validatePsqlRequiresC(command string, args []string) error {
	if command == "psql" {
		for _, a := range args {
			if a == "-c" || strings.HasPrefix(a, "--command=") {
				return nil
			}
		}
		return &ValidationError{Message: "psql requires the -c flag with a SQL command."}
	}
	return nil
}

func validateUnzipRequiresMode(command string, args []string) error {
	if command != "unzip" {
		return nil
	}
	hasMode := false
	for _, a := range args {
		if a == "-l" || a == "-p" {
			hasMode = true
			break
		}
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") {
			if strings.Contains(a[1:], "l") || strings.Contains(a[1:], "p") {
				hasMode = true
				break
			}
		}
	}
	if !hasMode {
		return &ValidationError{Message: "unzip requires -l (list) or -p (extract to stdout)."}
	}
	return nil
}

// validateCommandRequiresIntrospectionFlag rejects use of the POSIX `command`
// builtin without `-v` or `-V`. Without one of those flags, `command <cmd>` is
// not introspection — it executes <cmd>, turning the manifest into a universal
// bypass for every other allowlisted command. Requiring one of the
// introspection flags guarantees `command` only prints a description and exits.
func validateCommandRequiresIntrospectionFlag(command string, args []string) error {
	if command != "command" {
		return nil
	}
	for _, a := range args {
		if a == "-v" || a == "-V" {
			return nil
		}
	}
	return &ValidationError{Message: "command requires -v or -V (introspection only; bare 'command <cmd>' would execute <cmd> and bypass the allowlist)."}
}

func validateTarExtractRequiresStdout(command string, args []string) error {
	if command != "tar" {
		return nil
	}
	hasExtract := false
	hasStdout := false
	for _, a := range args {
		if a == "-O" || a == "--to-stdout" {
			hasStdout = true
		}
		if a == "-x" || a == "--extract" || a == "--get" {
			hasExtract = true
		}
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a[1:], "x") {
			hasExtract = true
		}
	}
	if hasExtract && !hasStdout {
		return &ValidationError{Message: "tar -x requires -O (extract to stdout)."}
	}
	return nil
}

func validateSQL(sql string) error {
	stripped := strings.TrimSpace(sql)
	if stripped == "" {
		return &ValidationError{Message: "Empty SQL command."}
	}

	content := strings.TrimSuffix(stripped, ";")
	if strings.Contains(content, ";") {
		return &ValidationError{Message: "Multiple SQL statements (internal semicolon) are not allowed."}
	}

	upper := strings.ToUpper(stripped)
	for _, prefix := range sqlAllowedPrefixes {
		if strings.HasPrefix(upper, strings.ToUpper(prefix)) {
			if strings.EqualFold(prefix, "WITH") {
				return validateWithCTE(stripped)
			}
			return nil
		}
	}

	return &ValidationError{Message: "SQL command is not a recognized read-only statement."}
}

// dmlKeywords are SQL keywords that perform writes. We reject these
// anywhere inside a CTE body to block writable CTEs such as
// "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d".
var dmlKeywords = []string{"DELETE", "INSERT", "UPDATE", "TRUNCATE", "DROP", "ALTER", "CREATE"}

func validateWithCTE(sql string) error {
	depth := 0
	lastClose := -1
	inSingleQuote := false

	for i := 0; i < len(sql); i++ {
		ch := sql[i]
		if ch == '\'' {
			inSingleQuote = !inSingleQuote
			continue
		}
		if inSingleQuote {
			continue
		}
		switch ch {
		case '(':
			depth++
			if depth == 1 {
				// Scan the body of this CTE definition for DML keywords.
				body, closeIdx := extractCTEBody(sql, i)
				if closeIdx == -1 {
					return &ValidationError{Message: "Malformed WITH CTE: no closing parenthesis found."}
				}
				if kw := containsDML(body); kw != "" {
					return &ValidationError{Message: fmt.Sprintf("WITH CTE body contains disallowed %s statement.", kw)}
				}
			}
		case ')':
			depth--
			if depth == 0 {
				lastClose = i
			}
		}
	}

	if lastClose == -1 {
		return &ValidationError{Message: "Malformed WITH CTE: no closing parenthesis found."}
	}

	remainder := strings.TrimSpace(sql[lastClose+1:])
	remainderUpper := strings.ToUpper(strings.TrimLeft(remainder, ", \t\n\r"))
	allowed := []string{"SELECT", "EXPLAIN", "SHOW", "WITH"}
	for _, kw := range allowed {
		if strings.HasPrefix(remainderUpper, kw) {
			return nil
		}
	}

	return &ValidationError{Message: "WITH CTE terminal statement is not read-only."}
}

// extractCTEBody returns the text inside the outermost parentheses starting
// at openIdx, respecting nesting and single-quote strings. It returns the
// body text and the index of the matching close paren (-1 if unbalanced).
func extractCTEBody(sql string, openIdx int) (string, int) {
	depth := 0
	inQuote := false
	for i := openIdx; i < len(sql); i++ {
		ch := sql[i]
		if ch == '\'' {
			inQuote = !inQuote
			continue
		}
		if inQuote {
			continue
		}
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return sql[openIdx+1 : i], i
			}
		}
	}
	return "", -1
}

// containsDML checks whether a SQL fragment contains a DML keyword at a word
// boundary (not inside a single-quoted string). Returns the matched keyword
// or "" if none found.
func containsDML(body string) string {
	upper := strings.ToUpper(body)
	for _, kw := range dmlKeywords {
		idx := 0
		for {
			pos := strings.Index(upper[idx:], kw)
			if pos == -1 {
				break
			}
			abs := idx + pos
			// Check word boundary before keyword.
			if abs > 0 && isWordChar(upper[abs-1]) {
				idx = abs + len(kw)
				continue
			}
			// Check word boundary after keyword.
			end := abs + len(kw)
			if end < len(upper) && isWordChar(upper[end]) {
				idx = abs + len(kw)
				continue
			}
			// Make sure the keyword is not inside a single-quoted string.
			if !isInsideQuote(body, abs) {
				return kw
			}
			idx = abs + len(kw)
		}
	}
	return ""
}

func isWordChar(ch byte) bool {
	return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_'
}

// isInsideQuote returns true if position pos in s is inside a single-quoted string.
func isInsideQuote(s string, pos int) bool {
	inside := false
	for i := 0; i < pos && i < len(s); i++ {
		if s[i] == '\'' {
			inside = !inside
		}
	}
	return inside
}

func checkRestrictedPath(arg string, m *manifest.Manifest) error {
	cleaned := path.Clean(arg)
	for _, restricted := range m.RestrictedPaths {
		if cleaned == restricted || strings.HasPrefix(cleaned, restricted+"/") {
			return &ValidationError{Message: fmt.Sprintf("Path '%s' is restricted for this command.", arg)}
		}
	}
	return nil
}

func checkGlobInPositional(arg string) error {
	if globChars.MatchString(arg) {
		return &ValidationError{Message: fmt.Sprintf("Glob pattern '%s' will not expand.", arg)}
	}
	return nil
}

func isNumericCountShorthand(arg string, m *manifest.Manifest) bool {
	if !regexp.MustCompile(`^-\d+$`).MatchString(arg) {
		return false
	}
	nFlag := m.GetFlag("-n")
	return nFlag != nil && nFlag.TakesValue && !nFlag.Deny
}
