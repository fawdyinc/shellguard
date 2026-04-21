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
//
// Tokens are defined up-front for characters that will appear in future grammar
// productions (PSSafeExpr, calculated properties, env refs). Today most of
// them have no valid use, so any input that produces them participle rejects
// at parse time — diagnoseParseError maps that rejection back to a targeted
// user message in ParsePowerShell. As grammar productions land that use these
// tokens, the corresponding rejections naturally flip to accepts.
var psLexer = lexer.MustSimple([]lexer.SimpleRule{
	{Name: "Whitespace", Pattern: `[ \t]+`},
	{Name: "HashOpen", Pattern: `@\{`},
	{Name: "HashClose", Pattern: `\}`},
	{Name: "Pipe", Pattern: `\|`},
	{Name: "DoubleColon", Pattern: `::`},
	{Name: "Eq", Pattern: `=`},
	{Name: "Semi", Pattern: `;`},
	{Name: "Comma", Pattern: `,`},
	{Name: "LBrace", Pattern: `\{`},
	{Name: "LParen", Pattern: `\(`},
	{Name: "RParen", Pattern: `\)`},
	{Name: "LBracket", Pattern: `\[`},
	{Name: "RBracket", Pattern: `\]`},
	// EnvRef must precede Dollar; case-insensitive "env" prefix.
	{Name: "EnvRef", Pattern: `\$[eE][nN][vV]:[a-zA-Z_][a-zA-Z0-9_]*`},
	{Name: "Dollar", Pattern: `\$`},
	{Name: "String", Pattern: `'[^']*'`},
	// DQString allows any non-quote byte in the body. Content safety (no $,
	// no backtick) is validated at parse time by the grammar productions
	// that accept DQString; until those land, DQString is unparseable.
	{Name: "DQString", Pattern: `"[^"]*"`},
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

// preScanRejects holds characters that have no representation in any grammar
// production — rejecting them before parsing gives a targeted error message
// faster than waiting for participle to fail. Every other character-level
// restriction is enforced by the grammar itself (see diagnoseParseError).
var preScanRejects = []struct {
	char    string
	message string
}{
	{"`", "Backtick escaping/continuation is not allowed."},
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
		return nil, diagnoseParseError(trimmed, err)
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

// preScanDangerous rejects characters that aren't in any grammar production,
// producing a targeted error message. Characters that are potentially valid
// in future productions (e.g., `{`, `$`, `"`, `(`, `)`) are deferred to the
// parser; diagnoseParseError translates participle's "unexpected token" error
// back into a user-friendly message for inputs the grammar still rejects.
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

		for _, pat := range redirectionPatterns {
			if i+len(pat) <= len(input) && input[i:i+len(pat)] == pat {
				return &ParseError{Message: "Output redirection is not allowed. Command output is captured automatically."}
			}
		}

		for _, dc := range preScanRejects {
			if string(ch) == dc.char {
				return &ParseError{Message: dc.message}
			}
		}
	}
	return nil
}

// diagnoseParseError inspects a failed parse and produces a targeted error
// message for inputs containing characters that the grammar doesn't yet
// accept. This is the translation layer that lets pre-scan shrink to just
// the always-invalid characters while preserving helpful error messages.
//
// Characters here match grammar productions that are either unreleased or
// constrained to specific positions. When a grammar workstream lands, its
// characters stop triggering parse failures and these messages never fire.
func diagnoseParseError(input string, parseErr error) error {
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

		switch ch {
		case '$':
			return &ParseError{Message: "Variable references ($) are not allowed. To read environment variables, use: Get-ChildItem Env:VARIABLE_NAME — then use the returned value literally in your next command."}
		case '"':
			return &ParseError{Message: "Double-quoted strings are not allowed (prevents variable interpolation). Use single quotes: '...'"}
		case '(', ')':
			return &ParseError{Message: "Subexpressions and method calls are not allowed. Use cmdlet parameters instead."}
		case '[', ']':
			return &ParseError{Message: "Subexpressions and method calls are not allowed. Use cmdlet parameters instead."}
		case '{':
			if i == 0 || input[i-1] != '@' {
				return &ParseError{Message: "Script blocks are not supported. Use simplified Where-Object syntax: Where-Object PropertyName -eq Value"}
			}
		case ';':
			if !insideHashtable(input, i) {
				return &ParseError{Message: "Statement separators (;) are not allowed. Use pipeline (|) to chain commands."}
			}
		}
	}

	return &ParseError{Message: fmt.Sprintf("PowerShell parse error: %v", parseErr)}
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
