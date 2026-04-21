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
	// no backtick) is enforced by validatePSPipeline at parse time.
	{Name: "DQString", Pattern: `"[^"]*"`},
	// SizeLiteral must precede Number so `1GB` is one token, not `1` + `GB`.
	{Name: "SizeLiteral", Pattern: `[0-9]+(?:KB|MB|GB|TB)`},
	{Name: "Number", Pattern: `[0-9]+`},
	// Flag must precede Minus so `-Name` lexes as a flag token, not minus + ident.
	{Name: "Flag", Pattern: `-[a-zA-Z_][a-zA-Z0-9_]*`},
	{Name: "Plus", Pattern: `\+`},
	{Name: "Minus", Pattern: `-`},
	{Name: "Slash", Pattern: `/`},
	{Name: "Percent", Pattern: `%`},
	// Ident allows dots, hyphens, wildcards (*), colons, and backslashes for
	// paths (C:\foo), env refs (Env:PATH), and wildcards (*.log). Comma-joined
	// lists like "Id,Name" are handled as a grammar-level PSCommaList.
	{Name: "Ident", Pattern: `[a-zA-Z_*][a-zA-Z0-9_.*:\\-]*`},
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

// PSValue is a comma-separated list of literals. PowerShell treats `a, b, c`
// as an array argument; we flatten it into a single comma-joined token string.
// A single value (no commas) has an empty Tail slice.
//
//nolint:govet
type PSValue struct {
	First *PSLiteral   `@@`
	Tail  []*PSLiteral `( "," @@ )*`
}

//nolint:govet
type PSLiteral struct {
	Hashtable *PSHashtable `  @@`
	Block     *PSExprBlock `| @@`
	String    *string      `| @String`
	DQString  *string      `| @DQString`
	EnvRef    *string      `| @EnvRef`
	Size      *string      `| @SizeLiteral`
	Number    *string      `| @Number`
	Ident     *PSIdentish  `| @@`
}

//nolint:govet
type PSIdentish struct {
	Head string `@Ident ( "-" @Ident )?`
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

// PSExprBlock is a safely-scoped script block: only a constrained expression
// grammar is accepted inside. Used for calculated properties (@{E={...}}) and
// Where/Sort/Group-Object script-block arguments.
//
//nolint:govet
type PSExprBlock struct {
	Expr *PSSafeExpr `LBrace @@ HashClose`
}

// PSSafeExpr is the root of the safe-expression sub-grammar. Deliberately
// narrow: no assignment, no call syntax outside the type-whitelisted static
// call form, no arbitrary subexpressions beyond grouping parens.
//
//nolint:govet
type PSSafeExpr struct {
	Or *PSOrExpr `@@`
}

//nolint:govet
type PSOrExpr struct {
	First *PSAndExpr  `@@`
	Rest  []*PSOrTail `@@*`
}

//nolint:govet
type PSOrTail struct {
	Op   string     `@("-or")`
	Expr *PSAndExpr `@@`
}

//nolint:govet
type PSAndExpr struct {
	First *PSCmpExpr   `@@`
	Rest  []*PSAndTail `@@*`
}

//nolint:govet
type PSAndTail struct {
	Op   string     `@("-and")`
	Expr *PSCmpExpr `@@`
}

//nolint:govet
type PSCmpExpr struct {
	Left *PSAddExpr `@@`
	Tail *PSCmpTail `@@?`
}

//nolint:govet
type PSCmpTail struct {
	Op    string     `@("-eq"|"-ne"|"-gt"|"-lt"|"-ge"|"-le"|"-like"|"-notlike"|"-match"|"-notmatch")`
	Right *PSAddExpr `@@`
}

//nolint:govet
type PSAddExpr struct {
	First *PSMulExpr   `@@`
	Rest  []*PSAddTail `@@*`
}

//nolint:govet
type PSAddTail struct {
	Op   string     `@("+"|"-")`
	Expr *PSMulExpr `@@`
}

//nolint:govet
type PSMulExpr struct {
	First *PSUnary     `@@`
	Rest  []*PSMulTail `@@*`
}

//nolint:govet
type PSMulTail struct {
	Op   string   `@("/"|"%")`
	Expr *PSUnary `@@`
}

//nolint:govet
type PSUnary struct {
	Neg  *string `@"-"?`
	Atom *PSAtom `@@`
}

//nolint:govet
type PSAtom struct {
	StaticCall *PSStaticCall `  @@`
	PipeVar    *PSPipeVar    `| @@`
	EnvRef     *string       `| @EnvRef`
	Size       *string       `| @SizeLiteral`
	Number     *string       `| @Number`
	String     *string       `| @String`
	DQString   *string       `| @DQString`
	Paren      *PSSafeExpr   `| "(" @@ ")"`
}

// PSPipeVar matches `$_` optionally followed by dotted property accessors.
// The Ident pattern includes `.` in its inner char class, so `$_.Status.Foo`
// lexes as Dollar + Ident("_.Status.Foo") — captured wholesale here.
//
//nolint:govet
type PSPipeVar struct {
	Ident string `Dollar @Ident`
}

// PSStaticCall matches `[Type]::Member` optionally followed by `(args)`.
// Type and Member identifiers are whitelisted during post-parse validation;
// the grammar only bounds the shape, not which types/members are safe.
//
//nolint:govet
type PSStaticCall struct {
	Type   string           `"[" @Ident "]" "::"`
	Member string           `@Ident`
	Call   *PSStaticArgList `@@?`
}

//nolint:govet
type PSStaticArgList struct {
	Args []*PSSafeExpr `"(" ( @@ ( "," @@ )* )? ")"`
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
	trimmed := strings.TrimSpace(stripPSComments(command))
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

	if err := validatePSPipeline(parsed); err != nil {
		return nil, err
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
			// $env:VAR is allowed (EnvRef). $_ would be allowed inside a script
			// block once that grammar lands. Other $ usage remains unsupported.
			if !looksLikeEnvRef(input, i) {
				return &ParseError{Message: "Variable references ($) are not allowed. Read environment variables via $env:VARNAME (e.g., $env:USERPROFILE)."}
			}
		case '"':
			// Bare $ or backtick inside a DQString is explicitly rejected by
			// validatePSValue with a targeted message; if we're diagnosing at
			// this point the content was safe but the position wasn't (e.g.,
			// DQString as a hashtable key). Preserve the historical message.
			return &ParseError{Message: "Double-quoted strings must not contain $ or backtick (prevents variable interpolation). Use single quotes: '...'"}
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

// validatePSPipeline walks the parsed AST to enforce invariants the grammar
// can't express: DQString bodies must not contain $ or backtick (interpolation
// prevention), and similar content-level checks.
func validatePSPipeline(p *PSPipeline) error {
	cmds := []*PSCommand{&p.First}
	for _, piped := range p.Rest {
		cmds = append(cmds, &piped.Command)
	}
	for _, cmd := range cmds {
		for _, arg := range cmd.Args {
			var v *PSValue
			switch {
			case arg.Flag != nil:
				v = arg.Flag.Value
			case arg.Positional != nil:
				v = &arg.Positional.Value
			}
			if v == nil {
				continue
			}
			if err := validatePSValue(v); err != nil {
				return err
			}
		}
	}
	return nil
}

func validatePSValue(v *PSValue) error {
	if v == nil {
		return nil
	}
	if err := validateLiteral(v.First); err != nil {
		return err
	}
	for _, t := range v.Tail {
		if err := validateLiteral(t); err != nil {
			return err
		}
	}
	return nil
}

func validateLiteral(l *PSLiteral) error {
	if l == nil {
		return nil
	}
	if l.DQString != nil {
		body := *l.DQString
		if len(body) >= 2 && body[0] == '"' && body[len(body)-1] == '"' {
			body = body[1 : len(body)-1]
		}
		if strings.ContainsAny(body, "$`") {
			return &ParseError{Message: "Double-quoted strings must not contain $ or backtick (prevents variable interpolation and escape sequences). Use single quotes: '...'"}
		}
	}
	if l.Hashtable != nil {
		for _, entry := range l.Hashtable.Entries {
			if err := validatePSValue(&entry.Value); err != nil {
				return err
			}
		}
	}
	if l.Block != nil {
		if err := validateSafeExpr(l.Block.Expr); err != nil {
			return err
		}
	}
	return nil
}

// allowedStaticTypes is the whitelist of [Type]::Member receivers. Matched
// case-insensitively against the parsed Type identifier.
var allowedStaticTypes = map[string]bool{
	"math":     true,
	"datetime": true,
	"timespan": true,
	"int":      true,
	"int64":    true,
}

// allowedStaticMembers is the whitelist of member names on the allowed types.
// Matched case-insensitively.
var allowedStaticMembers = map[string]bool{
	"round":        true,
	"floor":        true,
	"ceiling":      true,
	"abs":          true,
	"min":          true,
	"max":          true,
	"now":          true,
	"utcnow":       true,
	"today":        true,
	"fromseconds":  true,
	"fromminutes":  true,
	"fromhours":    true,
	"fromdays":     true,
	"maxvalue":     true,
	"minvalue":     true,
	"parse":        true,
}

func validateSafeExpr(e *PSSafeExpr) error {
	if e == nil || e.Or == nil {
		return nil
	}
	if err := validateAndExpr(e.Or.First); err != nil {
		return err
	}
	for _, t := range e.Or.Rest {
		if err := validateAndExpr(t.Expr); err != nil {
			return err
		}
	}
	return nil
}

func validateAndExpr(e *PSAndExpr) error {
	if err := validateCmpExpr(e.First); err != nil {
		return err
	}
	for _, t := range e.Rest {
		if err := validateCmpExpr(t.Expr); err != nil {
			return err
		}
	}
	return nil
}

func validateCmpExpr(e *PSCmpExpr) error {
	if err := validateAddExpr(e.Left); err != nil {
		return err
	}
	if e.Tail != nil {
		if err := validateAddExpr(e.Tail.Right); err != nil {
			return err
		}
	}
	return nil
}

func validateAddExpr(e *PSAddExpr) error {
	if err := validateMulExpr(e.First); err != nil {
		return err
	}
	for _, t := range e.Rest {
		if err := validateMulExpr(t.Expr); err != nil {
			return err
		}
	}
	return nil
}

func validateMulExpr(e *PSMulExpr) error {
	if err := validateUnary(e.First); err != nil {
		return err
	}
	for _, t := range e.Rest {
		if err := validateUnary(t.Expr); err != nil {
			return err
		}
	}
	return nil
}

func validateUnary(u *PSUnary) error {
	return validateAtom(u.Atom)
}

func validateAtom(a *PSAtom) error {
	if a == nil {
		return nil
	}
	switch {
	case a.StaticCall != nil:
		return validateStaticCall(a.StaticCall)
	case a.Paren != nil:
		return validateSafeExpr(a.Paren)
	case a.DQString != nil:
		s := *a.DQString
		body := s
		if len(body) >= 2 && body[0] == '"' && body[len(body)-1] == '"' {
			body = body[1 : len(body)-1]
		}
		if strings.ContainsAny(body, "$`") {
			return &ParseError{Message: "Double-quoted strings must not contain $ or backtick inside an expression. Use single quotes: '...'"}
		}
	}
	return nil
}

func validateStaticCall(c *PSStaticCall) error {
	typeName := strings.ToLower(c.Type)
	memberName := strings.ToLower(c.Member)
	if !allowedStaticTypes[typeName] {
		return &ParseError{Message: fmt.Sprintf("Type [%s] is not allowed in expressions. Allowed: math, datetime, timespan, int, int64.", c.Type)}
	}
	if !allowedStaticMembers[memberName] {
		return &ParseError{Message: fmt.Sprintf("Member %s is not allowed. Allowed: Round, Floor, Ceiling, Abs, Min, Max, Now, UtcNow, Today, FromSeconds, FromMinutes, FromHours, FromDays, Parse, MinValue, MaxValue.", c.Member)}
	}
	if c.Call != nil {
		for _, arg := range c.Call.Args {
			if err := validateSafeExpr(arg); err != nil {
				return err
			}
		}
	}
	return nil
}

// stripPSComments removes `#`-prefixed line comments outside single-quoted
// strings. LLMs sometimes emit explanatory comments before or alongside
// commands; dropping them here is more forgiving than failing parse.
func stripPSComments(input string) string {
	var b strings.Builder
	b.Grow(len(input))
	inSQ := false
	inDQ := false
	for i := 0; i < len(input); i++ {
		ch := input[i]
		switch {
		case ch == '\'' && !inDQ:
			inSQ = !inSQ
			b.WriteByte(ch)
		case ch == '"' && !inSQ:
			inDQ = !inDQ
			b.WriteByte(ch)
		case ch == '#' && !inSQ && !inDQ:
			// Skip to end of line.
			for i < len(input) && input[i] != '\n' {
				i++
			}
			if i < len(input) {
				b.WriteByte('\n')
			}
		default:
			b.WriteByte(ch)
		}
	}
	return b.String()
}

// looksLikeEnvRef returns true if the byte at position pos starts a
// `$env:VARNAME` token. Used by diagnoseParseError to decide whether a `$` is
// the start of a permitted env ref or something else we should reject.
func looksLikeEnvRef(input string, pos int) bool {
	if pos+5 >= len(input) || input[pos] != '$' {
		return false
	}
	suffix := input[pos+1:]
	if len(suffix) < 4 {
		return false
	}
	e, n, v, colon := suffix[0], suffix[1], suffix[2], suffix[3]
	return (e == 'e' || e == 'E') && (n == 'n' || n == 'N') && (v == 'v' || v == 'V') && colon == ':'
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

// renderPSValue converts a parsed value (a comma-separated literal list) back
// to its string form. Single literals produce a single token; comma-lists
// produce `a,b,c` with no spaces.
func renderPSValue(v *PSValue) string {
	if v == nil {
		return ""
	}
	s := renderLiteral(v.First)
	for _, t := range v.Tail {
		s += "," + renderLiteral(t)
	}
	return s
}

func renderLiteral(l *PSLiteral) string {
	if l == nil {
		return ""
	}
	switch {
	case l.Hashtable != nil:
		return renderHashtable(l.Hashtable)
	case l.Block != nil:
		return renderExprBlock(l.Block)
	case l.String != nil:
		s := *l.String
		if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
			return s[1 : len(s)-1]
		}
		return s
	case l.DQString != nil:
		s := *l.DQString
		if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
			return s[1 : len(s)-1]
		}
		return s
	case l.EnvRef != nil:
		return *l.EnvRef
	case l.Size != nil:
		return *l.Size
	case l.Number != nil:
		return *l.Number
	case l.Ident != nil:
		return renderIdentish(l.Ident)
	}
	return ""
}

func renderIdentish(id *PSIdentish) string {
	return id.Head
}

func renderExprBlock(b *PSExprBlock) string {
	if b == nil {
		return ""
	}
	return "{" + renderSafeExpr(b.Expr) + "}"
}

func renderSafeExpr(e *PSSafeExpr) string {
	if e == nil || e.Or == nil {
		return ""
	}
	return renderOrExpr(e.Or)
}

func renderOrExpr(e *PSOrExpr) string {
	s := renderAndExpr(e.First)
	for _, t := range e.Rest {
		s += " " + t.Op + " " + renderAndExpr(t.Expr)
	}
	return s
}

func renderAndExpr(e *PSAndExpr) string {
	s := renderCmpExpr(e.First)
	for _, t := range e.Rest {
		s += " " + t.Op + " " + renderCmpExpr(t.Expr)
	}
	return s
}

func renderCmpExpr(e *PSCmpExpr) string {
	s := renderAddExpr(e.Left)
	if e.Tail != nil {
		s += " " + e.Tail.Op + " " + renderAddExpr(e.Tail.Right)
	}
	return s
}

func renderAddExpr(e *PSAddExpr) string {
	s := renderMulExpr(e.First)
	for _, t := range e.Rest {
		s += t.Op + renderMulExpr(t.Expr)
	}
	return s
}

func renderMulExpr(e *PSMulExpr) string {
	s := renderUnary(e.First)
	for _, t := range e.Rest {
		s += t.Op + renderUnary(t.Expr)
	}
	return s
}

func renderUnary(u *PSUnary) string {
	prefix := ""
	if u.Neg != nil {
		prefix = "-"
	}
	return prefix + renderAtom(u.Atom)
}

func renderAtom(a *PSAtom) string {
	switch {
	case a.StaticCall != nil:
		return renderStaticCall(a.StaticCall)
	case a.PipeVar != nil:
		return "$" + a.PipeVar.Ident
	case a.EnvRef != nil:
		return *a.EnvRef
	case a.Size != nil:
		return *a.Size
	case a.Number != nil:
		return *a.Number
	case a.String != nil:
		return *a.String
	case a.DQString != nil:
		return *a.DQString
	case a.Paren != nil:
		return "(" + renderSafeExpr(a.Paren) + ")"
	}
	return ""
}

func renderStaticCall(c *PSStaticCall) string {
	s := "[" + c.Type + "]::" + c.Member
	if c.Call == nil {
		return s
	}
	s += "("
	for i, arg := range c.Call.Args {
		if i > 0 {
			s += ","
		}
		s += renderSafeExpr(arg)
	}
	s += ")"
	return s
}

// renderHashtable serializes a parsed hashtable back to @{Key=Value; ...} form.
// String-ish values are single-quoted for consistent PowerShell semantics;
// script blocks (calculated properties) and numeric values are emitted raw so
// PowerShell evaluates them rather than treating them as literal strings.
// A hashtable entry with a comma-list value is rendered as its comma-joined
// form (no extra quoting of the list as a whole).
func renderHashtable(ht *PSHashtable) string {
	var b strings.Builder
	b.WriteString("@{")
	for i, entry := range ht.Entries {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(entry.Key)
		b.WriteString("=")
		if len(entry.Value.Tail) == 0 && entry.Value.First != nil {
			renderHashEntrySingle(&b, entry.Value.First)
		} else {
			// Multi-literal list: join raw without blanket quoting.
			b.WriteString(renderPSValue(&entry.Value))
		}
	}
	b.WriteString("}")
	return b.String()
}

func renderHashEntrySingle(b *strings.Builder, l *PSLiteral) {
	switch {
	case l.Block != nil:
		b.WriteString(renderExprBlock(l.Block))
	case l.Hashtable != nil:
		b.WriteString(renderHashtable(l.Hashtable))
	case l.Number != nil, l.Size != nil, l.EnvRef != nil:
		b.WriteString(renderLiteral(l))
	default:
		val := renderLiteral(l)
		b.WriteString("'")
		b.WriteString(strings.ReplaceAll(val, "'", "''"))
		b.WriteString("'")
	}
}
