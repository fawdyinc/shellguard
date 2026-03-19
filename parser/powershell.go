// Package parser provides a safe PowerShell dialect parser using participle.
//
// The grammar defines a restricted subset of PowerShell that covers ~90% of
// diagnostic value while rejecting dangerous constructs (variables, script
// blocks, redirections, etc.). Security is enforced by the grammar itself:
// anything not in the grammar is rejected by the parser.
package parser

import (
	"fmt"
	"strings"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer"
)

// PowerShell lexer definition. Order matters: longer/more-specific tokens first.
var psLexer = lexer.MustSimple([]lexer.SimpleRule{
	{Name: "Whitespace", Pattern: `[ \t]+`},
	{Name: "HashOpen", Pattern: `@\{`},
	{Name: "HashClose", Pattern: `\}`},
	{Name: "Pipe", Pattern: `\|`},
	{Name: "Eq", Pattern: `=`},
	{Name: "Semi", Pattern: `;`},
	{Name: "Comma", Pattern: `,`},
	{Name: "String", Pattern: `'[^']*'`},
	{Name: "Number", Pattern: `[0-9]+`},
	{Name: "Flag", Pattern: `-[a-zA-Z_][a-zA-Z0-9_]*`},
	// Ident allows dots, hyphens, wildcards (*), colons, and backslashes for
	// paths (C:\foo), env refs (Env:PATH), wildcards (*.log), and comma-separated
	// property lists (Id,Name,CPU).
	{Name: "Ident", Pattern: `[a-zA-Z_*][a-zA-Z0-9_.*:,\\-]*`},
})

// PSPipeline is the top-level grammar rule: one or more commands separated by |.
// Struct tags use participle grammar syntax, not standard Go struct tags.
//
//nolint:govet
type PSPipeline struct {
	First PSCommand  `@@`
	Rest  []*PSPiped `@@*`
}

//nolint:govet
type PSPiped struct {
	Command PSCommand `"|" @@`
}

//nolint:govet
type PSCommand struct {
	Name string        `@Ident ( "-" @Ident )?`
	Args []*PSArgument `@@*`
}

//nolint:govet
type PSArgument struct {
	Flag       *PSFlag       `  @@`
	Positional *PSPositional `| @@`
}

//nolint:govet
type PSFlag struct {
	Name  string   `@Flag`
	Value *PSValue `@@?`
}

//nolint:govet
type PSPositional struct {
	Value PSValue `@@`
}

//nolint:govet
type PSValue struct {
	Hashtable *PSHashtable `  @@`
	String    *string      `| @String`
	Number    *string      `| @Number`
	Ident     *string      `| @Ident ( "-" @Ident )?`
}

//nolint:govet
type PSHashtable struct {
	Entries []*PSHashEntry `HashOpen @@* HashClose`
}

//nolint:govet
type PSHashEntry struct {
	Key   string  `@Ident "="`
	Value PSValue `@@`
	Semi  *string `@Semi?`
}

var psParser = participle.MustBuild[PSPipeline](
	participle.Lexer(psLexer),
	participle.Elide("Whitespace"),
)

// dangerousChars maps characters that should be rejected with actionable messages
// before parsing. These are checked in order.
var dangerousChars = []struct {
	char    string
	message string
}{
	{"$", "Variable references ($) are not allowed. To read environment variables, use: Get-ChildItem Env:VARIABLE_NAME — then use the returned value literally in your next command."},
	{"`", "Backtick escaping/continuation is not allowed."},
	{"\"", "Double-quoted strings are not allowed (prevents variable interpolation). Use single quotes: '...'"},
	{"(", "Subexpressions and method calls are not allowed. Use cmdlet parameters instead."},
	{")", "Subexpressions and method calls are not allowed. Use cmdlet parameters instead."},
	{"&", "The call operator (&) is not allowed. Use cmdlet names directly."},
}

// redirectionPatterns checks for output redirection operators.
var redirectionPatterns = []string{">>", "2>", ">"}

// ParsePowerShell parses a PowerShell command string into a Pipeline using the
// safe PowerShell dialect grammar. Returns actionable error messages for
// rejected constructs.
func ParsePowerShell(command string) (*Pipeline, error) {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return nil, &ParseError{Message: "Empty command."}
	}
	if len(trimmed) > MaxCommandLength {
		return nil, &ParseError{Message: fmt.Sprintf("Command too long (%d bytes, max %d).", len(trimmed), MaxCommandLength)}
	}

	// Pre-scan for dangerous characters outside single-quoted strings.
	if err := preScanDangerous(trimmed); err != nil {
		return nil, err
	}

	parsed, err := psParser.ParseString("", trimmed)
	if err != nil {
		return nil, &ParseError{Message: fmt.Sprintf("PowerShell parse error: %v", err)}
	}

	segments, err := convertPSPipeline(parsed)
	if err != nil {
		return nil, err
	}

	if len(segments) > MaxPipeSegments {
		return nil, &ParseError{Message: fmt.Sprintf("Too many pipeline segments (%d, max %d).", len(segments), MaxPipeSegments)}
	}

	return &Pipeline{Segments: segments}, nil
}

// preScanDangerous rejects characters that are not in the safe grammar.
// It skips characters inside single-quoted strings.
func preScanDangerous(input string) error {
	inSingleQuote := false
	for i := 0; i < len(input); i++ {
		ch := input[i]
		if ch == '\'' {
			inSingleQuote = !inSingleQuote
			continue
		}
		if inSingleQuote {
			continue
		}

		// Check redirections (multi-char patterns first).
		for _, pat := range redirectionPatterns {
			if i+len(pat) <= len(input) && input[i:i+len(pat)] == pat {
				return &ParseError{Message: "Output redirection is not allowed. Command output is captured automatically."}
			}
		}

		// Check semicolons outside @{}.
		if ch == ';' {
			// Check if we're inside a hashtable by looking for preceding @{
			if !insideHashtable(input, i) {
				return &ParseError{Message: "Statement separators (;) are not allowed. Use pipeline (|) to chain commands."}
			}
			continue
		}

		// Check script blocks: { without preceding @
		if ch == '{' && (i == 0 || input[i-1] != '@') {
			return &ParseError{Message: "Script blocks are not supported. Use simplified Where-Object syntax: Where-Object PropertyName -eq Value"}
		}

		for _, dc := range dangerousChars {
			if string(ch) == dc.char {
				return &ParseError{Message: dc.message}
			}
		}
	}
	return nil
}

// insideHashtable checks if position pos is inside a @{...} block.
func insideHashtable(input string, pos int) bool {
	depth := 0
	inQuote := false
	for i := 0; i < pos; i++ {
		ch := input[i]
		if ch == '\'' {
			inQuote = !inQuote
			continue
		}
		if inQuote {
			continue
		}
		if i+1 < len(input) && ch == '@' && input[i+1] == '{' {
			depth++
			i++ // skip '{'
		} else if ch == '}' && depth > 0 {
			depth--
		}
	}
	return depth > 0
}

// convertPSPipeline converts the participle AST to our Pipeline type.
func convertPSPipeline(ps *PSPipeline) ([]PipelineSegment, error) {
	segments := make([]PipelineSegment, 0, 1+len(ps.Rest))

	seg, err := convertPSCommand(&ps.First, "")
	if err != nil {
		return nil, err
	}
	segments = append(segments, seg)

	for _, piped := range ps.Rest {
		seg, err := convertPSCommand(&piped.Command, "|")
		if err != nil {
			return nil, err
		}
		segments = append(segments, seg)
	}

	return segments, nil
}

// convertPSCommand converts a parsed PS command into a PipelineSegment.
// Command names are normalized to lowercase for manifest lookup.
func convertPSCommand(cmd *PSCommand, operator string) (PipelineSegment, error) {
	name := strings.ToLower(cmd.Name)
	args := make([]string, 0, len(cmd.Args))

	for _, arg := range cmd.Args {
		if arg.Flag != nil {
			args = append(args, arg.Flag.Name)
			if arg.Flag.Value != nil {
				args = append(args, renderPSValue(arg.Flag.Value))
			}
		} else if arg.Positional != nil {
			args = append(args, renderPSValue(&arg.Positional.Value))
		}
	}

	if len(args) > MaxArgsPerSegment {
		return PipelineSegment{}, &ParseError{Message: fmt.Sprintf("Too many arguments (%d, max %d).", len(args), MaxArgsPerSegment)}
	}

	return PipelineSegment{
		Command:  name,
		Args:     args,
		Operator: operator,
	}, nil
}

// renderPSValue converts a parsed value back to its string representation.
func renderPSValue(v *PSValue) string {
	if v.Hashtable != nil {
		return renderHashtable(v.Hashtable)
	}
	if v.String != nil {
		// Strip surrounding quotes, return raw content
		s := *v.String
		if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
			return s[1 : len(s)-1]
		}
		return s
	}
	if v.Number != nil {
		return *v.Number
	}
	if v.Ident != nil {
		return *v.Ident
	}
	return ""
}

// renderHashtable serializes a parsed hashtable back to @{Key='Value'; ...} form.
func renderHashtable(ht *PSHashtable) string {
	var b strings.Builder
	b.WriteString("@{")
	for i, entry := range ht.Entries {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(entry.Key)
		b.WriteString("=")
		val := renderPSValue(&entry.Value)
		// Always single-quote string values in hashtables for safety
		b.WriteString("'")
		b.WriteString(strings.ReplaceAll(val, "'", "''"))
		b.WriteString("'")
	}
	b.WriteString("}")
	return b.String()
}
