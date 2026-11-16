---
name: sql-injection-sqlite-variants
description: SQLite specific SQL injection. Covers SQLite syntax constraints, no native sleep workaround through heavy queries, ATTACH DATABASE file write, and sqlite_master metadata enumeration. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["sqlite injection", "sqlite sqli", "sqlite_master", "attach database", "sqlite error"]
cwe: [CWE-89]
owasp: [A03:2021, A05:2025]
attack: [T1190]
capec: [CAPEC-66]
related: [sql-injection, sql-injection-mysql-variants, sql-injection-mssql-variants, sql-injection-oracle-variants]
parent: sql-injection
---

# Sql Injection Sqlite Variants - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md)

## Mechanism and Preconditions

SQLite SQL injection works within tighter dialect constraints: there is no `SLEEP`, so time-blind confirmation relies on a CPU-heavy expression such as a nested `randomblob()`, and schema enumeration reads `sqlite_master` because there is no `information_schema`. The parser still separates single-quoted literals from double-quoted or bracketed identifiers, so a value that closes its quote becomes grammar and an un-mapped sort column becomes an identifier slot. SQLite errors are terse, such as `unrecognized token` or `no such column`, and `JSON_EXTRACT` can turn a malformed path into an error-based oracle. Higher impact is narrow: `ATTACH DATABASE` can write a file and `load_extension` can load code, but both are usually disabled in embedded builds, so the finding is the grammar break and impact depends on the host binding.

- **Precondition chain:** A request value reaches a SQLite statement in a literal or identifier position, the binding does not parameterise it, and a SQLite channel survives such as a terse parse error, a UNION-shaped result, a boolean row swing, or a `randomblob` delay.
- **Readable differential:** The same query with a benign literal versus one that closes the quote or injects a heavy `randomblob` expression; a finding exists when rows, a SQLite parse error, or elapsed time diverge and revert when the value is bound.
- **Empirical grounding:** CWE-89 sits under OWASP Top 10:2025 A05:2025 Injection; SOURCES.md carries no SQLite-specific SQL advisory, so this stays at taxonomy level and anchors on the dialect constraints around timing and metadata.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed to match the SQLite case **THEN** start at the parent class [`sql-injection`](../sql-injection/SKILL.md) first (1 hop)
2. **IF** the value is bound by the SQLite binding and no identifier is interpolated **THEN** classify as a non-finding and consider [`authorization-and-idor`](../authorization-and-idor/SKILL.md)
3. **IF** no timing primitive exists because SQLite lacks SLEEP **THEN** use a nested `randomblob` heavy query for the delay oracle
4. **IF** the error surface shows unrecognized token or no such column **THEN** drive error-based confirmation from that channel before timing
5. **IF** metadata is needed **THEN** read `sqlite_master` rather than information_schema
6. **IF** the embedded engine is actually MySQL or Postgres **THEN** switch to [`sql-injection-mysql-variants`](../sql-injection-mysql-variants/SKILL.md) (1 hop)
7. **IF** the sink is an ORM raw fragment over SQLite **THEN** switch to [`sql-injection-orm-and-query-builder`](../sql-injection-orm-and-query-builder/SKILL.md) (1 hop)
8. **IF** the stored value is executed by a later read **THEN** switch to [`sql-injection-second-order`](../sql-injection-second-order/SKILL.md) (1 hop)
9. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md)
10. **IF** no reachable sink and no SQLite channel remain after inspection **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Value is bound by the SQLite driver | [`authorization-and-idor`](../authorization-and-idor/SKILL.md) | Parsing is safe; row ownership is the only remaining question |
| Raw fragment reaches SQLite via an ORM | [`sql-injection-orm-and-query-builder`](../sql-injection-orm-and-query-builder/SKILL.md) | The splice is a builder method, not hand-written SQL |
| Value executes on a later read | [`sql-injection-second-order`](../sql-injection-second-order/SKILL.md) | Deferred parse is a distinct invariant |
| Need parent class methodology | [`sql-injection`](../sql-injection/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the SQLite statement and classify the position.** Mark whether the value sits in a single-quoted literal or a double-quoted or bracketed identifier, and whether the host binding such as sqlite3, better-sqlite3, or Room parameterises it.
2. **Pick a SQLite channel given the dialect limits.** There is no `SLEEP`, so timing means a heavy `randomblob` expression; errors are terse tokens; `JSON_EXTRACT` gives an error oracle; `UNION` needs the exact column count. Choose the least intrusive available.
3. **Capture a two-value baseline.** Run two benign literals and note rows, any terse SQLite error, and elapsed time; embedded SQLite latency is low, so the noise floor is small and a heavy-query delay stands out clearly.
4. **Probe the quote or identifier boundary.** Append a single quote to trigger `unrecognized token`, or send an unknown sort token to trigger `no such column`; the branch follows the position you classified, not a scattershot of payloads.
5. **Establish column count before any UNION reasoning.** Increment an `ORDER BY` ordinal until SQLite raises an out-of-range error to fix the shape, keeping the probe read-only and structure-only.
6. **Stop condition.** Halt when the probe yields a SQLite differential that reverts under a bound value, or shows no change across two baselines, or would require `ATTACH DATABASE` to write a file or `load_extension` to load code. The first confirms, the second is a non-finding, the third is out of scope.
7. **State what counts as proof.** Proof is one changed literal on an identical request producing a reproducible move in rows, a specific SQLite token error, or a `randomblob` delay above the small baseline, plus the source line where the value is concatenated. A terse SQLite error without input control is not proof.
8. **Close with the structural fix.** Use parameter binding for every literal, resolve sort and column tokens through a server-side allowlist, and keep `load_extension` disabled and the database file read-only where possible. Verify by replaying the token-error and heavy-query probes against the patched build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `unrecognized token` or `near "...": syntax error` in the response | Proves the SQLite lexer reached attacker input, a token error a bound parameter would not surface |
| `no such column` raised by a sort or filter token | Proves an identifier slot is interpolated on SQLite rather than mapped server-side |
| Elapsed time tracking a nested `randomblob()` expression | Proves time-blind injection on SQLite, which has no SLEEP, so the delay must be CPU-bound to be observable |
| `sqlite_master` referenced to enumerate schema | Proves metadata extraction through the SQLite catalog table, the dialect stand-in for information_schema |
| A `JSON_EXTRACT` malformed-path error reflected back | Proves an error-based oracle specific to the SQLite JSON1 functions |
| `ATTACH DATABASE` or `load_extension` reachable in the statement | Proves a file-write or code-load primitive on SQLite, usually disabled in embedded builds so impact is host-dependent |
| A fixed small column count confirmed via out-of-range `ORDER BY` | Proves UNION feasibility on SQLite where the exact arity must match before any set-based read |

## Worked Contrast

**Vulnerable pattern:**

```python
import sqlite3

def find_item(db: sqlite3.Connection, request):
    name = request.GET.get("name", "")
    # Value concatenated into a single-quote literal; SQLite parses the closing quote
    return db.execute("SELECT id, price FROM items WHERE name = '" + name + "'").fetchall()
```

**Hardened pattern:**

```python
import sqlite3

def find_item(db: sqlite3.Connection, request):
    name = request.GET.get("name", "")
    # '?' placeholder binds the value; the quote context belongs to the driver
    return db.execute("SELECT id, price FROM items WHERE name = ?", (name,)).fetchall()
```

**Why this matters:** The defect concatenates the value into a single-quoted literal, so a quote re-opens SQLite grammar and surfaces a token error or alters the row set. The fix uses a `?` placeholder so the sqlite3 driver binds the value and the same input stays data.

## When It Is NOT This Issue

- **Terse error from honest bad input:** a `no such column` caused by a genuinely wrong field name is not injection unless a quote or expression changes the parse.
- **Heavy query from legitimate load:** a slow response under concurrency can mimic a `randomblob` delay, so only a delay that scales with the expression and reverts when bound counts.
- **load_extension disabled:** reaching `load_extension` in grammar does not mean code loads, because most embedded builds compile it out, so do not claim code execution.
- **Read-only database file:** an `ATTACH DATABASE` write attempt against a read-only file cannot create the file, so report the injection, not the file write.
- **Bound value with quotes intact:** a `?`-bound value keeps its quotes in the data without ever parsing.
- **Full-text or virtual-table syntax:** FTS match syntax that looks odd is engine feature use, not an injected boundary, absent a grammar break.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `sql-injection-sqlite-variants` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `sql-injection-sqlite-variants` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: sql-injection-sqlite-variants
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-89 | Mapping: T1190]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md) - Blue Detection/Defense Counterpart
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`sql-injection-mysql-variants`](../sql-injection-mysql-variants/SKILL.md) - Web and Application (leaf)
- [`sql-injection-mssql-variants`](../sql-injection-mssql-variants/SKILL.md) - Web and Application (leaf)
- [`sql-injection-oracle-variants`](../sql-injection-oracle-variants/SKILL.md) - Web and Application (leaf)
- [`sql-injection-postgres-variants`](../sql-injection-postgres-variants/SKILL.md) - Web and Application (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `sql-injection-sqlite-variants` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-89, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 24 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/payloads_all_the_things (10), CYBER_CPT/oxdf (7), OffsecCyber (3), CYBER_CPT/L5/ctf_search (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 13 det / 0 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
