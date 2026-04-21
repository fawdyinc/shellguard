# PowerShell Parser Expansion (v3 — script support)

## Status: sketch for decision, not a commitment

This plan extends v2 to support multi-statement scripts with local variables
and basic control flow — `if`, `foreach`, variable assignment. Everything in
v2 still applies; this document only covers the delta.

**Recommendation at the bottom: probably don't do this yet.** Build v2 first,
measure whether agents actually hit the "I need variables" wall on the corpus
harness, then revisit. The sketch here is what v3 would look like if that
measurement says yes.

## Scope shift from v2

v2 supports one pipeline per `shellguard_execute` call. Agents chain
investigation as separate tool calls, carrying state in their own context:

```
call 1: Get-Service w3svc
call 2: (reads output, decides)  Get-Process -Name w3wp
```

v3 supports a script as one tool call, with local state:

```powershell
$svc = Get-Service w3svc
if ($svc.Status -eq 'Running') {
    Get-Process -Name w3wp | Select-Object Id, WorkingSet
} else {
    Get-EventLog -LogName System -Newest 10 -Source 'Service Control Manager'
}
```

Same end result, one round-trip instead of two or three.

## Three execution models

Before grammar, pick one:

### Model A: Flattened one-shot script (recommended if we do this)

Each `shellguard_execute` receives a self-contained script. No state crosses
tool calls. Parse → validate every statement → reconstruct as one PowerShell
program → send whole thing via `-EncodedCommand` → return captured output.

- **Pros:** Stateless like today. No session management. Existing WinRM
  transport unchanged. Timeout + output limits work as-is.
- **Cons:** LLM doesn't see intermediate pipeline outputs — only the final
  captured stdout. If the script errors mid-execution, attribution is coarse
  ("the script failed" vs "statement 3 failed"). Mitigation: surface
  PowerShell's error records in stderr, which agents already read.

### Model B: Persistent session (rejected)

Shellguard maintains a long-running PowerShell runspace per agent session.
Variables persist across `shellguard_execute` calls. Conceptually powerful
but adds: session lifecycle management, session-to-agent binding, memory
leaks on abandoned sessions, state bleeding between investigations, and a
fundamentally different safety story (variable values from previous calls
flow into new ones — hard to reason about). Rejected.

### Model C: Single pipeline plus local-scope `let` (partial)

Like Model A but only within a single pipeline expression — no statement
separators, no `if`, no `foreach`. Just `$x = Get-Service; $x.Status`. Saves
very little over v2 (since calculated properties + `Where-Object` already
cover most cases) while adding grammar complexity. Rejected.

**The rest of this plan assumes Model A.**

## Grammar additions

v2's `PSSafeExpr` stays. v3 adds a statement layer above it.

```
PSScript      ::= PSStatement (Terminator PSStatement)* Terminator?
Terminator    ::= ";" | "\n"
PSStatement   ::= PSAssignment
                | PSIfStatement
                | PSForeachStatement
                | PSPipeline

PSAssignment  ::= "$" Ident "=" (PSPipeline | PSSafeExpr)

PSIfStatement ::= "if" "(" PSSafeExpr ")" PSBlock
                  ("elseif" "(" PSSafeExpr ")" PSBlock)*
                  ("else" PSBlock)?

PSForeachStatement ::= "foreach" "(" "$" Ident "in" PSIterable ")" PSBlock
PSIterable    ::= PSPipeline | PSSafeExpr

PSBlock       ::= "{" PSScript "}"
```

Plus: extend `PSSafeExpr`'s atom set so any `$Ident` defined by a preceding
`PSAssignment` or bound by `foreach` is a valid atom. Property access carries
through: `$svc.Status.ToString()` would need method-call support (still out
of scope via the `MemberWhitelist` — property access only).

### Intentional omissions

- **No `while` / `do` / `for` loops.** `foreach` covers the diagnostic cases;
  arbitrary loops invite infinite iteration, DoS, and script-bomb patterns.
- **No `try/catch`.** Error handling happens at the shellguard boundary;
  scripts that want to "see" an error should check preconditions with `if`.
- **No `function` / `filter` definitions.** If you need abstraction, use
  more `shellguard_execute` calls.
- **No `switch` statement.** `if/elseif/else` chains are enough and the
  `switch` grammar is surprisingly intricate.
- **No `return` keyword.** Output is the captured stdout of the whole script.
- **No variable interpolation in double-quoted strings.** Still banned. Use
  `-f` format operator with single-quoted format string + argument list:
  `'{0} is {1}' -f $name, $status`. Actually… the format operator needs
  `-f`, which is a binary op on strings. Worth adding to `PSSafeExpr`.

### Variable scoping rules

- `PSAssignment` introduces `$name` into the enclosing `PSScript`.
- `foreach ($x in ...)` introduces `$x` into the foreach's `PSBlock` only.
- Block scope: `PSBlock` inherits outer names; assignments inside a block
  do NOT leak out (Model A is PowerShell's default; we enforce it).
- Name resolution at parse time: every `$name` reference must resolve to an
  in-scope assignment or a foreach binding, OR to `$_` (pipeline), OR to
  `$env:X` (env ref). Unresolved → parse error with "Variable `$name` was
  not defined earlier in this script."

This catches typos AND prevents an agent from accidentally getting a `$`
reference past the parser by writing `$svc.Status` without first assigning
`$svc`.

## Safety additions over v2

1. **Defined-names tracker.** Parser maintains a scope stack during AST walk.
   Every `$Ident` reference (outside `$_` / `$env:X`) is resolved or
   rejected. Implementation: one pass over the AST after parse; ~50 lines.

2. **Statement count limit.** Cap at ~20 statements per script. Prevents
   pathological programs without killing legitimate investigations.

3. **Block nesting limit.** Cap at 3 levels of `if` / `foreach` nesting.
   Same reason.

4. **Foreach iterable must be bounded.** The iterable in `foreach ($x in
   <expr>)` is a `PSPipeline` whose command must be manifested. No
   `foreach ($i in 1..1000000)` — range literals above a cap (say, 1000)
   are rejected.

5. **No cmdlet validation bypass via variables.** Every `PSPipeline` inside
   a script is validated against the manifest exactly like the top-level
   pipeline is today. A variable can hold a string but cannot be invoked as
   a cmdlet — the grammar doesn't admit `& $cmd` or `$cmd arg1 arg2`.

6. **Execution timeout stays at the WinRM layer.** Already in place.

## Reconstruction

`ReconstructPowerShellCommand` in `winrm/reconstruct.go` currently takes a
`*parser.Pipeline`. Rename to `ReconstructPowerShellPipeline` and add
`ReconstructPowerShellScript(*parser.Script) string` that walks statements,
emitting:

- Assignment: `$name = <rendered RHS>`
- If: `if (<cond>) { <block> } elseif (<cond>) { <block> } else { <block> }`
- Foreach: `foreach ($x in <iter>) { <block> }`
- Pipeline: unchanged from v2

Round-trip property test extends: `Parse(Reconstruct(Parse(s))) == Parse(s)`
for every corpus entry, including script-form entries.

## Workstreams (delta over v2)

Everything from v2's workstreams still runs. v3 adds:

| Workstream | Days | Risk | Notes |
| --- | --- | --- | --- |
| **F. Statement grammar** | 3-4 | medium | Depends on v2's Workstream C landing. |
| **G. Scope resolver** | 1-2 | medium | Name resolution pass + tests. |
| **H. Script reconstruction** | 2 | medium | Round-trip test is the gate. |
| **I. Corpus: script-shaped** | 0.5 | none | Harvest multi-step patterns from recorded sessions; seed v2's corpus harness with script-form entries. Drives whether v3 is worth it. |
| **J. Error attribution** | 1 | low | Map PowerShell error records back to statement index when possible. |

Total: ~1.5-2 weeks on top of v2.

## What v3 unlocks (honest accounting)

**Yes:**
- Conditional investigation: `if (service is running) { check process } else { check eventlog }`
- Per-item correlation: `foreach ($svc in Get-Service -Name w3*) { Get-Process -Id $svc.ProcessId }`
- Derived values: assign a computed value once, reuse in multiple pipelines
- Reducing round-trips on investigation flows that today take 3-5 calls

**No:**
- Anything with mutation (still denied)
- Anything needing `try/catch`, `while`, `switch`, `function`
- Error recovery (script fails → whole script fails)
- Interactive prompts (none of these are interactive anyway)
- Arbitrary .NET — the `TypeWhitelist` / `MemberWhitelist` from v2 still
  bounds static calls

## Cost vs. v2

| Axis | v2 | v3 |
| --- | --- | --- |
| Grammar productions | ~35 | ~55 |
| Test surface (fuzz inputs, corpus entries) | 1x | ~3x |
| Reconstruction complexity | Linear per-pipeline | Recursive tree walk |
| Error-message quality | Per-cmdlet | Degrades — multi-statement context |
| Implementation time | ~1 week | ~2-3 weeks total |
| Fuzz-surface-to-feature ratio | Good | Worse |

The grammar roughly doubles. Fuzz-harness budget needs to scale with it.

## Why I recommend against doing this (yet)

1. **LLMs are natively good at chaining tool calls.** The agentic loop
   *is* the conditional: "I'll check the service, then based on the output
   decide what to do." Forcing conditional logic into PowerShell script form
   works *against* the model's strengths. Anthropic's models in particular
   are trained to reason between tool calls, not to write correct
   multi-statement PowerShell.

2. **Single-pipeline PowerShell is already more expressive than it looks.**
   Most v3 use cases collapse to v2 patterns:
   - "For each running service, show its top process" →
     `Get-Process -IncludeUserName | Where-Object { $_.ProcessName -in (Get-Service -ErrorAction Ignore | Where-Object Status -eq Running).Name } | Sort-Object CPU -Descending | Select-Object -First 10`
   - "If service is running show A else show B" → two `shellguard_execute`
     calls with an agent decision in between. One extra round-trip.

3. **The corpus harness from v2 will tell us if this is needed.** If the
   3dx-style sessions recur and show agents clearly hitting the "I need
   variables" wall — repeatedly writing the same thing in two separate
   calls that could be one script — that's evidence to build v3. Without
   that evidence, we're building speculatively.

4. **Error messages degrade in a way that hurts agents.** Today a rejection
   is "Get-WmiObject is not allowed — use Get-CimInstance". In v3, a
   20-line script with one bad cmdlet produces "parse/validation error at
   statement 7." Agents burn more turns debugging than they save from
   consolidation.

5. **Security review cost is not proportional to feature value.** The fuzz
   surface roughly triples. Every new production needs adversarial testing.
   For a feature that's mostly already expressible in v2 form, the ratio is
   poor.

## When to revisit

Build v2. Run the corpus harness for a month. If you see:

- Sessions where the agent writes the same investigative pattern across
  3+ calls, where a variable assignment would have collapsed them
- Agents explicitly asking (in chain-of-thought) for `if` or `foreach`
- Cases where per-item correlation is needed and no single-pipeline
  formulation works

…then v3 is justified. Until then, v2 is the bet.

## References

- `docs/plans/2026-04-20-powershell-parser-expansion-v2.md` — the
  foundational plan this extends. v3 is strictly additive on top of v2;
  v2 must land first regardless.
- Source session: `ses_252a83796ffedk7cXAmutOY5tq`. The 3dx investigation
  used ~18 pipelines; a rough count of those that *could* have been
  consolidated into scripts: 2-3 pairs, saving ~3 round-trips out of 18.
  Low enough that v3 isn't obviously a win.
