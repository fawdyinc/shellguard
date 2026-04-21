# PowerShell Parser Expansion (v2)

## Problem

The PowerShell parser in `feat/winrm-powershell` rejects idiomatic read-only
constructs that real agents emit. A recorded Fawdy session
(`ses_252a83796ffedk7cXAmutOY5tq`, "3dx") hit two distinct parser rejections
and ~6 manifest misses in 18 `shellguard_execute` calls — burning LLM turns on
self-correction for commands that are structurally safe.

The two parser failures:
1. Calculated properties — `Select-Object @{N='Used(GB)';E={[math]::Round($_.Used/1GB,2)}}`
   rejected because `{` is blanket-banned.
2. Literal double-quoted paths — `"C:\path\to\file"` rejected because `"` is
   blanket-banned, even with no `$` or backtick in the body.

v1 of this plan proposed four tiers of grammar expansion plus manifest
additions. This v2 keeps the same end state but fixes three design issues in v1:

1. **Split safety boundary.** v1 kept the existing pre-scan + grammar split,
   which forces every new construct to coordinate changes in two places. Each
   tier of v1 had inconsistencies between its grammar productions and its
   "Pre-scan becomes narrower" spec (Tier 1.1 needs `(` for `PSStaticCall` but
   v1 only unbans `(` in Tier 3.2).
2. **Reconstruction treated as an afterthought.** v1 mentions `renderHashtable`
   only in a testing bullet. But `parser/powershell.go:287-304` unconditionally
   single-quotes hashtable values. If you extend `PSHashEntry.Value` with a
   `PSExprBlock` variant, reconstruction will silently emit
   `@{E='{[math]::Round(...)}'}` — a quoted string literal, not an executable
   block. Reconstruction correctness is a parse-time concern.
3. **Prioritization by intuition, not data.** v1 ranks tiers by
   `(impact × frequency) / cost`. The only empirical input is one session. A
   corpus-driven harness turns "intuition" into "fails N of M recorded
   commands," so reprioritization is mechanical.

v2 addresses all three before any grammar change lands.

## Design shift: grammar as the single safety boundary

Today, `ParsePowerShell` runs `preScanDangerous` (`parser/powershell.go:150`)
before `psParser.ParseString`. Pre-scan rejects characters that are unsafe if
they appear anywhere: `$`, `` ` ``, `"`, `(`, `)`, `&`, redirections, `;`
outside hashtables, `{` outside hashtable-opens. The participle grammar is a
second layer that decides which tokens form a valid command.

The tension: every expansion needs both layers updated in lockstep. A `$_`
accessor needs pre-scan to permit `$` (conditionally) AND the grammar to
recognize `$_` as a new production. Getting these out of sync produces either
false positives (v1 Tier 1.1 as written) or silent unsafe parses.

The fix: **let the grammar be the safety boundary. Pre-scan only rejects
characters that aren't in the lexer at all.** Anything lexable either forms a
valid parse tree or gets rejected by the parser with a targeted error. The
invariant becomes: *if `ParsePowerShell` returns nil error, the reconstructed
string executes exactly the operations in the parsed AST — no injection
surface.*

Concretely, `preScanDangerous` shrinks to reject exactly:
- `` ` `` (backtick — not in any grammar production)
- `&` (call operator — not in any grammar production)
- `>`, `>>`, `2>` (redirections — not in any grammar production)
- Any other character that isn't in the lexer alphabet

Every other restriction moves into the grammar + participle's error reporting.
`{`, `$`, `"`, `(`, `)`, `;` all become lexer tokens whose validity is
determined by position in the parse tree.

This is not a security weakening. The grammar already enforces safety today —
pre-scan is belt-and-suspenders. The weakening would only happen if the
grammar were permissive; we're designing it tightly (see "Safe expression
sub-grammar" below) and backing that with fuzz tests.

## Workstreams

v1's tiers mixed workstreams with very different risk and cadence profiles.
Separating them lets each land independently:

| Workstream | Risk | Days | Unblocks |
| --- | --- | --- | --- |
| **A. Corpus harness** | none | 0.5 | Data-driven prioritization for B/C |
| **B. Safety refactor** | medium | 1-2 | All grammar work |
| **C. Grammar extensions** | medium | 3-5 | Depends on B |
| **D. Manifest additions** | low | 1 | Independent |
| **E. Error messages** | low | 0.5 | Independent |

A, D, E can start immediately. B is prerequisite for C.

### Workstream A — Corpus harness (do first)

Build `parser/corpus_test.go` that reads YAML fixtures from
`parser/testdata/corpus/*.yaml`, each entry of the form:

```yaml
command: "Get-PSDrive -PSProvider FileSystem | Select-Object Name, @{N='Used(GB)';E={[math]::Round($_.Used/1GB,2)}}"
source: ses_252a83796ffedk7cXAmutOY5tq
expect: parses         # or "rejects" with a reason tag
reason: calculated-property-in-select
```

Seed the corpus with the full 18-command 3dx session. The test runs
`ParsePowerShell` on each entry and groups failures by `reason`. When a tier
lands, rerun to see which reason tags flipped green.

This replaces v1's "`test/powershell-real-commands.go` or similar" bullet with
something that runs in `go test` and drives prioritization.

### Workstream B — Safety refactor

Changes:
1. `parser/powershell.go:97-109` — shrink `dangerousChars` to `` ` `` and `&`
   only. Delete `{` handling from `preScanDangerous`. Leave redirections check
   at line 163-167.
2. `parser/powershell.go:18-33` — add lexer tokens for characters that will
   appear in future productions but have no valid use today: `LBrace` (`{`),
   `RBrace` (`}`), `LParen` (`(`), `RParen` (`)`), `LBracket` (`[`),
   `RBracket` (`]`), `DoubleColon` (`::`), `Dollar` (`$`), `Dot` (`.`),
   `DQString` (see C.2), `EnvRef` (see C.6).
3. Add **negative grammar tests** proving the parser rejects every pattern
   pre-scan used to catch: `cmd > file`, `cmd & other`, `cmd; cmd`, bare
   `{block}`, bare `(expr)`, `$var`. Each must produce a parser error, not
   panic.
4. Add **fuzz target** `parser/fuzz_powershell_test.go` using Go's native
   fuzzing. Seed with the corpus from A. Assertion: for every input the fuzzer
   produces, either `ParsePowerShell` returns an error, or
   `ReconstructPowerShellCommand(parsed)` produces a string whose token set
   is a subset of the input's token set (no new identifiers, no new operators).
   This is the machine-checkable form of the safety invariant.

The fuzz target is non-negotiable. Without it, moving safety into the grammar
is just vibes.

### Workstream C — Grammar extensions

Depends on B. Design the new productions as a single reusable sub-grammar,
not scattered per-feature.

**C.1 Safe expression sub-grammar (`PSSafeExpr`)**

Define once, reuse in four positions. This is the core correctness bet.

```
PSSafeExpr   ::= PSOrExpr
PSOrExpr     ::= PSAndExpr ("-or" PSAndExpr)*
PSAndExpr    ::= PSNotExpr ("-and" PSNotExpr)*
PSNotExpr    ::= "-not"? PSCmpExpr
PSCmpExpr    ::= PSAddExpr (CmpOp PSAddExpr)?
PSAddExpr    ::= PSMulExpr (("+" | "-") PSMulExpr)*
PSMulExpr    ::= PSUnary   (("*" | "/" | "%") PSUnary)*
PSUnary      ::= "-"? PSAtom
PSAtom       ::= PSPipeVar
              |  PSStaticCall
              |  PSEnvRef
              |  Number
              |  String
              |  DQString              ; validated: no "$" or backtick
              |  SizeLiteral           ; 1GB, 512MB, 2.5KB, 1TB
              |  "(" PSSafeExpr ")"
PSPipeVar    ::= "$_" ("." Ident)*
PSStaticCall ::= "[" TypeWhitelist "]" "::" MemberWhitelist "(" PSArgList? ")"
PSArgList    ::= PSSafeExpr ("," PSSafeExpr)*
PSEnvRef     ::= "$env:" Ident
CmpOp        ::= "-eq" | "-ne" | "-gt" | "-lt" | "-ge" | "-le"
              |  "-like" | "-notlike" | "-match" | "-notmatch"
              |  "-contains" | "-notcontains" | "-in" | "-notin"
TypeWhitelist    ::= "math" | "datetime" | "timespan" | "int" | "int64"
MemberWhitelist  ::= Round | Floor | Ceiling | Abs | Min | Max
                  |  Now | UtcNow | Today
                  |  FromSeconds | FromMinutes | FromHours | FromDays
```

`SizeLiteral` (v1's `/GB` / `/MB` shorthand) becomes a Number × constant
folded at parse time. Simpler than a binary operator: `1GB` lexes as a single
Number-with-suffix token and `PSAtom` treats it as a numeric literal with value
`1073741824`. No new operator needed.

`PSSafeExpr` appears in exactly four positions:
1. Inside `@{Key=E={<PSSafeExpr>}}` — calculated properties.
2. Inside `Where-Object { <PSSafeExpr> }` — filter expressions.
3. Inside `Sort-Object { <PSSafeExpr> }` — sort key selectors.
4. Inside `Group-Object { <PSSafeExpr> }` — group key selectors.

**C.2 Literal double-quoted strings**

New `DQString` lexer token: `"[^"$` `]*"`. Emit token; at parse-time, strip the
quotes. No `$` interpolation is possible because `$` can't appear in the token
body. Treat as equivalent to a single-quoted string.

**C.3 `$env:X` reads**

`EnvRef` lexer token: `\$env:[A-Za-z_][A-Za-z0-9_]*`. **Must precede `Ident`
in the lexer rule list** (`parser/powershell.go:18`) — today's `Ident` pattern
matches `env:PATH` as one token because `:` is in the char class. The `$`
prefix makes `EnvRef` unambiguous.

Coordinate redaction with `secrets.ScrubSecrets` (see Reference below).
Env refs matching `*_TOKEN`, `*_KEY`, `*_SECRET`, `*_PASSWORD`,
`*_CREDENTIAL` get their *resolved output* redacted at the post-execution
stage already implemented in the secrets plan. No changes needed in the
parser — `$env:GITHUB_TOKEN` reconstructs verbatim, the scrubber handles the
leak. Document this cross-cutting concern in the secrets design's Phase 2
section.

**C.4 Context-aware `{` error messages**

With pre-scan no longer catching `{`, rejection comes from participle. Wrap
its error in `parser/powershell.go:132-134` to route by context:

- Error at position right after a cmdlet name like `Where-Object` →
  "Simplified syntax required: `Where-Object PropertyName -eq Value`, or use
  the safe-expression form: `Where-Object { $_.Prop -eq 'x' }`."
- Error at position inside `@{Key=` → "Calculated properties only accept safe
  expressions: arithmetic on `$_.Prop`, `[math]::Round`, etc."
- Elsewhere → "Script blocks are only allowed inside `Where-Object`,
  `Sort-Object`, `Group-Object`, or `@{E={...}}` calculated properties."

Implementation: scan the input once before passing to participle to record
positions of `|`, cmdlet-name starts, and `@{...=` sites. If participle
errors, use the error position to pick the matching message. ~30 lines in a
new `parser/powershell_errors.go`.

**C.5 Reconstruction coverage**

**This is the step v1 missed.** For each new grammar production, add a
corresponding renderer:
- `renderExprBlock(b *PSExprBlock) string` — emits `{<expr>}` with no quoting
  of the body, recursively rendering sub-atoms.
- `renderPSSafeExpr(e *PSSafeExpr) string` — operator-preserving round-trip.
- `renderHashtable` (`parser/powershell.go:287`) must route `PSExprBlock`
  values through `renderExprBlock`, not single-quote them as strings.

Add a **round-trip property test**: for every corpus entry that parses,
`ReconstructPowerShellCommand(ParsePowerShell(input))` must re-parse to an
equivalent AST. This catches reconstruction bugs the moment they're
introduced.

### Workstream D — Manifest additions

No grammar dependency. One PR, 16 new YAMLs mirroring
`manifest/manifests/powershell/get-service.yaml`:

| Cmdlet | Notable flags / gotchas |
| --- | --- |
| `Get-CimInstance` | `-ClassName`, `-Query`, `-Filter`. **Explicitly deny `-MethodName`.** WQL in `-Query` is treated as opaque string; manifest rejection of `-MethodName` is the real safety gate. |
| `ForEach-Object` | Allow both `ForEach-Object <Prop>` (simplified) and `ForEach-Object -MemberName <Prop>`. Script-block form rejected unless Workstream C lands. |
| `Group-Object` | Property-name positional, `-NoElement`. |
| `Compare-Object` | `-ReferenceObject`, `-DifferenceObject` via piped args. |
| `Get-LocalUser` / `Get-LocalGroup` / `Get-LocalGroupMember` | Local account audit. |
| `Get-NetFirewallRule` / `Get-NetFirewallPortFilter` / `Get-NetFirewallAddressFilter` | Firewall inspection. |
| `Get-NetRoute` / `Get-NetNeighbor` / `Get-DnsClientCache` / `Resolve-DnsName` | Network state. |
| `Test-NetConnection` | TCP port; distinct from ICMP `Test-Connection`. |
| `Get-ScheduledTask` / `Get-ScheduledTaskInfo` | Scheduled jobs. |
| `Get-SmbShare` / `Get-SmbConnection` / `Get-SmbSession` | File shares. |
| `Get-Acl` | Read-only ACL. |
| `Get-ExecutionPolicy` / `Get-Host` / `Get-Culture` / `Get-Location` / `Get-History` | Environment info. |
| `Get-Package` / `Get-AppxPackage` | Installed software. |
| `Get-PhysicalDisk` / `Get-Partition` | Disk topology. |
| `Join-Path` / `Split-Path` / `Resolve-Path` | Safe path manipulation. |
| `Get-Help` / `Get-Command` | **Prioritize.** Self-discovery reduces manifest-miss rate without adding more cmdlets — the agent can look up what's allowed. |

Also add a `denied/` entry for `Get-WmiObject` with `replacement:
Get-CimInstance` for the Workstream E message.

### Workstream E — Error messages & ergonomics

Independent of grammar. Three low-risk improvements:

1. **Closest-cmdlet suggestions.** When manifest validation rejects a cmdlet,
   Levenshtein-match against the allow list and suggest. Special-case
   deprecated → modern mappings from a small table (`Get-WmiObject →
   Get-CimInstance`, `Test-Connection → Test-NetConnection -TcpPort`).
   Validator change, ~40 lines.
2. **Comment stripping.** Strip `#...` to end-of-line before parsing (outside
   single-quoted strings). LLMs emit explanatory comments; today they break
   parsing.
3. **Common diagnostic flags.** `-ErrorAction <value>`, `-WarningAction
   <value>`, `-Verbose`, `-InformationAction <value>` allowed on any cmdlet
   whose manifest category is `services | networking | filesystem | system |
   utility`. Implement as a manifest-level default merged into per-cmdlet
   flag lists at load time.

## Design decisions (resolving v1's open questions)

v1 left four questions open. v2 picks defaults so implementation isn't blocked:

1. **Parens in `PSSafeExpr`** → **yes.** `"(" PSSafeExpr ")"` is in the grammar
   above. Scoped parens inside the safe-expression production don't open the
   top-level `(` ban; the grammar admits `(` *only* as part of `PSSafeExpr` or
   `PSStaticCall`. Without them, `-and` / `-or` precedence becomes painful.
2. **WQL validation in `-Query`** → **no parser-level validation.** Pass WQL
   as an opaque single-quoted string. Safety comes from the manifest rejecting
   `-MethodName` / `Invoke-CimMethod`. WQL's own semantics are read-only for
   `SELECT ... FROM`; if we later find an exploitable `CALL` or method-invoke
   syntax, revisit.
3. **`ForEach-Object -MemberName`** → **accept both forms.** Current grammar
   handles `-MemberName <value>` natively via `PSFlag`. Simplified positional
   form `ForEach-Object Name` also already parses. Just list both in the
   manifest.
4. **Env var redaction** → **delegate to `secrets.ScrubSecrets`.** Document
   in this plan and in the secrets design's Phase 2 section. No parser change.

## Non-goals

Unchanged from v1:
- Write operations stay denied (`Set-*`, `New-*`, `Remove-*`, `Start-*`,
  `Stop-*`, `Restart-*`, `Invoke-*`).
- Arbitrary .NET reflection (`[Type]::GetType().GetMethod(...).Invoke(...)`)
  — the `TypeWhitelist` and `MemberWhitelist` in `PSStaticCall` make this
  impossible by construction.
- CredSSP / delegation / auth flow changes.
- `cmd.exe` / CMD syntax.

## Verification

Each workstream lands as its own commit with:

- **A:** Corpus YAML + `TestCorpus` in `parser/corpus_test.go`.
- **B:** Fuzz target + negative grammar tests. CI runs fuzz for 60s per PR.
- **C:** Per-production parse test + rejection test for the nearby-dangerous
  variant (e.g., `@{E={Invoke-Expression 'rm'}}` must still reject) + the
  round-trip reconstruction property test.
- **D:** Manifest YAMLs + `manifest_test.go` coverage + end-to-end test
  through `ShellguardTool.Execute` with a mocked WinRM executor that asserts
  the reconstructed command matches expectations.
- **E:** Unit tests for comment stripping, suggestion matching, and default
  flag merging.

Post-landing: run the corpus harness against fresh session recordings. Every
new rejection reason becomes a corpus entry and either a grammar ticket or a
deliberate non-goal.

## References

- v1 of this plan: `docs/plans/2026-04-20-powershell-parser-expansion.md`.
  Kept for history; v2 supersedes.
- Secrets design (env var redaction coordination point):
  `docs/plans/2026-02-13-secrets-protection-design.md` — the `ScrubSecrets`
  post-execution stage at its Phase 2 already handles the redaction patterns
  `$env:X` would need.
- Source session: `ses_252a83796ffedk7cXAmutOY5tq` ("3dx" investigation).
  Seed the corpus with its full 18-command trace.
