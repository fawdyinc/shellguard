# PowerShell Parser Expansion

## Problem

The PowerShell parser and manifest set introduced in `feat/winrm-powershell`
covers ~90% of trivially-safe diagnostic commands, but real agent sessions hit
false positives often enough that the LLM wastes turns self-correcting. From a
recorded Fawdy session (`ses_252a83796ffedk7cXAmutOY5tq`, "3dx") investigating a
3DEXPERIENCE server, two distinct parser rejections and several manifest misses
came up within ~20 commands.

This plan groups the gaps by impact and implementation cost so we can land the
easy wins first without destabilizing the grammar.

## Findings from the 3dx session

Of 18 `shellguard_execute` invocations, 2 hit parser-level rejections:

### 1. Calculated property in `Select-Object`

```powershell
Get-PSDrive -PSProvider FileSystem `
  | Select-Object Name, @{N='Used(GB)';E={[math]::Round($_.Used/1GB,2)}}, ...
```

Error: `Script blocks are not supported. Use simplified Where-Object syntax:
Where-Object PropertyName -eq Value`

Structurally a false positive. Calculated properties (`@{N='label';E={expr}}`)
are the idiomatic read-only pattern for renaming/transforming columns. The
pre-scan rejects them because of the `{` after `E=`, and the error message
misdirects the LLM toward `Where-Object`, which isn't even present in the
command.

### 2. Double-quoted string literal

```powershell
Get-Content -Path "C:\DassaultSystemes\R2026x\3DSpace\logs\mxtrace.log" -Tail 50
```

Error: `Double-quoted strings are not allowed (prevents variable interpolation).
Use single quotes: '...'`

Technically correct but over-broad. The double-quote ban exists to prevent `$`
interpolation. A literal path that contains no `$` or `` ` `` is equivalent to a
single-quoted string and is safe.

### Manifest misses (non-parser)

Not in this session, but trivially reachable next queries for the same
investigation that would have hit "cmdlet not allowed":

- `Get-CimInstance Win32_Service` (modern replacement for `Get-WmiObject`)
- `Get-NetFirewallRule`, `Get-ScheduledTask`
- `ForEach-Object`, `Group-Object`
- `Test-NetConnection`, `Resolve-DnsName`

## Proposal

Four tiers, ordered by `(impact × frequency) / implementation cost`.

### Tier 1 — Ship first

**1.1 Calculated properties in `Select-Object`**

Extend the grammar so `@{Key=Value}` hashtable values can include a constrained
expression-block form:

```
PSHashEntry ::= Ident "=" ( PSValue | PSExprBlock )
PSExprBlock ::= "{" PSExpr "}"
PSExpr      ::= PSTerm (BinOp PSTerm)*
PSTerm      ::= "$_" ("." Ident)*
              | Number
              | PSStaticCall
              | "(" PSExpr ")"   ← maybe; see open questions
PSStaticCall ::= "[" TypeName "]" "::" Ident "(" PSArgList ")"
BinOp       ::= "+" | "-" | "*" | "/" | "%"
              | "/GB" | "/MB" | "/KB" | "/TB"   ← shorthand for binary / with the corresponding constant
TypeName    ::= "math"   ← whitelist
Ident       ::= (in PSStaticCall)  "Round" | "Floor" | "Ceiling" | "Abs" | "Min" | "Max"
```

Everything outside this grammar stays rejected. The `{` pre-scan check needs to
skip blocks that match `PSExprBlock` positionally (inside a hashtable `E=`
binding). This is the single biggest correctness bump.

**1.2 Double-quoted strings when safe**

Change `dangerousChars` so `"` is not a blanket reject. Instead, in the lexer
add a `DQString` token and validate its contents at parse time: reject if the
token body contains `$` or `` ` ``, accept otherwise. Emitted value is the
verbatim string minus surrounding quotes. This costs one additional lexer rule
and a ~5-line validator.

**1.3 Context-aware error messages**

The "Script blocks are not supported" message is emitted from `preScanDangerous`
for every `{` without regard to context. Route the message through the parser
state so the suggestion matches what the user was actually trying to do:

- Inside `Where-Object`/`ForEach-Object` position → suggest simplified syntax.
- Inside a hashtable value after `E=` → suggest the calculated-property form
  (after Tier 1.1 lands, this should be accepted; before then, the message
  should explain the restriction, not point at `Where-Object`).
- Elsewhere → keep the current message.

**1.4 Manifest additions (no grammar changes needed)**

Add allow manifests for:

| Cmdlet | Notes |
| --- | --- |
| `Get-CimInstance` | `-ClassName`, `-Query`, `-Filter`. Explicitly reject `-MethodName` / `Invoke-CimMethod` path. |
| `ForEach-Object` | Allow only the simplified form `ForEach-Object <PropertyName>`. Script-block form stays blocked. |
| `Group-Object` | Any property name, `-NoElement`. |
| `Compare-Object` | Input via piped args. |
| `Get-LocalUser`, `Get-LocalGroup`, `Get-LocalGroupMember` | Local account audit. |
| `Get-NetFirewallRule`, `Get-NetFirewallPortFilter`, `Get-NetFirewallAddressFilter` | Firewall inspection. |
| `Get-NetRoute`, `Get-NetNeighbor`, `Get-DnsClientCache`, `Resolve-DnsName` | Network state. |
| `Test-NetConnection` | TCP port connectivity (not ICMP — that's `Test-Connection`). |
| `Get-ScheduledTask`, `Get-ScheduledTaskInfo` | Scheduled jobs. |
| `Get-SmbShare`, `Get-SmbConnection`, `Get-SmbSession` | File shares. |
| `Get-Acl` | Read-only ACL inspection. |
| `Get-ExecutionPolicy`, `Get-Host`, `Get-Culture`, `Get-Location`, `Get-History` | Environment info. |
| `Get-Package`, `Get-AppxPackage` | Installed software inventory. |
| `Get-PhysicalDisk`, `Get-Partition` | Disk topology. |
| `Join-Path`, `Split-Path`, `Resolve-Path` | Path manipulation without string concat. |
| `Get-Help`, `Get-Command` | Self-discovery — lets the agent find allowed cmdlets without us having to teach it. |

Each gets a minimal YAML with common read-only flags. Mirror the structure of
`get-service.yaml`.

### Tier 2 — Medium effort, large unlock

**2.1 `$_` pipeline variable in constrained contexts**

Relax the blanket `$` ban to allow `$_` followed by zero or more `.Identifier`
accessors, but **only inside** one of:

- `Where-Object { ... }`
- `Sort-Object { ... }` key selector
- `Group-Object { ... }` key selector
- Calculated-property `E={...}` (from Tier 1.1)

Use the same constrained expression grammar as Tier 1.1 but extend with:

- `-eq`, `-ne`, `-gt`, `-lt`, `-ge`, `-le`, `-like`, `-match`, `-notmatch`
- `-and`, `-or`, `-not`
- String literals (single- or safe-double-quoted)

This unlocks compound filters like
`Where-Object { $_.Status -eq 'Running' -and $_.StartType -eq 'Automatic' }`,
which aren't expressible in the simplified syntax.

**2.2 Environment variable literal reads**

Add a lexer token `EnvRef` matching `$env:[A-Za-z_][A-Za-z0-9_]*` (no substring
operations, no interpolation). Treat it as a safe value equivalent to a string
literal. Saves a round-trip vs the current
`Get-ChildItem Env:X` → read value → use literal workflow.

**2.3 Range literal `1..10`**

Minor lexer tweak; used for index slicing like `Select-Object -Index 0..9`.
Accept `<Number>..<Number>` as a single token.

### Tier 3 — Only if demand is clear

**3.1 Static type members** (`[DateTime]::Now`, `[Environment]::MachineName`)

Allow `[TypeName]::Member` as a read accessor where `TypeName` is on a
whitelist. Parens (method calls) are the hard part — either extend the
whitelist to specific `[Type]::Method(...)` pairs, or stop at property access
only. Property-only is much safer but less useful.

**3.2 Dot-accessor on subexpressions** (`(Get-Date).AddDays(-7)`)

Requires lifting the `(` ban, which opens significant grammar surface area.
Most workflows can avoid this using cmdlet parameters (`Get-Date -Date ...`).
Deprioritize unless specific use cases emerge.

**3.3 Single-quote escape doubling** (`'it''s'`)

Lexer change to accept `''` inside single-quoted strings. Rare in diagnostic
contexts.

### Tier 4 — Ergonomics

**4.1 Comments (`# ...`)**

Strip single-line comments during pre-scan. LLMs sometimes emit explanatory
`# ...` before commands; today these break parsing.

**4.2 Common diagnostic flags**

Several read-only flags appear in nearly every `Get-*` cmdlet:
`-ErrorAction SilentlyContinue|Ignore|Continue`, `-WarningAction SilentlyContinue`,
`-Verbose`, `-InformationAction SilentlyContinue`. Centralize these as a
manifest-level default allowlist applicable to any command whose name matches
`Get-*` / `Test-*` / `Measure-*` / `Format-*` / `Select-*` / `Sort-*` / etc.,
rather than per-manifest.

**4.3 Manifest-miss suggestions**

When a parsed cmdlet isn't on the allow list, include suggestions for the
closest allowed cmdlets. For example, `Get-WmiObject is not allowed. For the
same information, use Get-CimInstance.`. Validator change, not parser.

## Implementation notes

### Grammar changes (`parser/powershell.go`)

Tier 1.1 and 2.1 share an expression sub-grammar. Factor it into a
`PSSafeExpr` production used in two positions:
- Inside hashtable `E={...}` values.
- Inside `Where-Object { ... }` / `Sort-Object { ... }` / `Group-Object { ... }` arguments.

Pre-scan's `{` check needs to become parser-state-aware. One approach: drop the
pre-scan rejection of `{`, let the parser reject unstructured blocks with a
targeted error when a `{` appears outside the allowed positions. Requires
confidence that the parser can't be tricked into accepting a block in a
disallowed position — worth adding fuzz tests for.

### Pre-scan becomes narrower

After these changes, `preScanDangerous` only rejects:
- `` ` `` (backtick) — no line continuation, no escape sequences
- `&` — call operator
- Output redirections (`>`, `>>`, `2>`)
- `(`, `)` (unless Tier 3.2)
- `$` (unless followed by `_` or `env:`, per Tier 2.1 / 2.2)
- `"` (unless the string body is safe, per Tier 1.2)
- `{` (unless in an allowed position, per Tier 1.1 / 2.1)
- `;` outside hashtables (unchanged)

### Testing

For each new construct:

- A positive parse test demonstrating the new grammar accepts the pattern.
- A negative test for the nearby-but-dangerous variant (e.g., calculated
  property with `Invoke-Expression` inside the `E={...}` block must still be
  rejected).
- Fuzz the parser against the expression sub-grammar to confirm no injection
  via nested constructs.
- An end-to-end test through `ShellguardTool.Execute` against a mock WinRM
  executor, so the reconstruct path (`winrm/reconstruct.go`) emits the
  expected PowerShell.

## Open questions

1. **Do we want `(PSExpr)` parentheses for grouping inside the safe-expression
   grammar?** They're convenient but re-open the blanket `(` rejection in a
   scoped way. Lean yes for ergonomics; audit carefully.
2. **`Get-CimInstance` with `-Query`.** The query is a WQL string. Do we
   validate WQL (SELECT-only, no CALL), or trust WQL's inherent read-only-ness
   for the main language and rely on the manifest rejecting `-MethodName`?
   Probably the latter for v1.
3. **`ForEach-Object` simplified form.** The grammar can accept
   `ForEach-Object <PropertyName>`, but some agents instead write
   `ForEach-Object -MemberName <Prop>`. Accept the `-MemberName` flag form as
   equivalent.
4. **Env var redaction.** If we allow `$env:VARNAME`, should we redact known
   secret-y names (`*_TOKEN`, `*_KEY`, `*_PASSWORD`, `*_SECRET`) at the output
   layer? The secrets-protection design already contemplates this pipeline.
   Coordinate with that.

## Non-goals

- **Write / mutation operations.** The denied manifests stay denied.
  `Invoke-*` stays banned. `Set-*`, `New-*`, `Remove-*`, `Start-*`, `Stop-*`,
  `Restart-*` all stay banned.
- **Arbitrary `.NET` reflection.** No `[Type]::GetType().GetMethod(...).Invoke(...)`.
- **CredSSP / delegation / remote authentication flow changes.** Out of scope.
- **CMD syntax.** Only PowerShell. `cmd.exe` stays denied.

## Verification

Each tier lands as its own commit with:
- Grammar + test updates for parser changes.
- New manifest YAMLs + `manifest_test.go` coverage.
- A smoke test runner (`test/powershell-real-commands.go` or similar) that
  takes a list of real commands harvested from recorded Fawdy sessions and
  asserts they parse + validate successfully. Add the 3dx session's full
  command set as the seed corpus.
- Manual verification against a live EC2 Windows box (record the session so
  next iteration has fresh data).
