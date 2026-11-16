---
name: sql-injection-mssql-variants
description: Microsoft SQL Server specific SQL injection. Covers WAITFOR DELAY timing, stacked queries, xp_cmdshell and sp_OACreate escalation, OPENROWSET and linked server exfiltration, and error-based conversion paths. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["mssql injection", "sql server injection", "waitfor delay", "xp_cmdshell", "openrowset"]
cwe: [CWE-89]
owasp: [A03:2021, A05:2025]
attack: [T1190]
capec: [CAPEC-66]
related: [sql-injection, sql-injection-mysql-variants, sql-injection-oracle-variants, sql-injection-postgres-variants]
parent: sql-injection
---

# Sql Injection Mssql Variants - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md)

## Mechanism and Preconditions

On Microsoft SQL Server the injection surface is shaped by T-SQL grammar. Value positions can be bound by the driver, while identifier positions such as a sort column, a TOP count, or a table name cannot and must resolve through a server-side map. SQL Server uniquely supports batch separation with a semicolon, so stacked statements are a real escalation; its reliable timing primitive is WAITFOR DELAY rather than a function, and its richest in-band oracle is a CONVERT or CAST error that embeds the target value in a type-conversion message. Comments are the double-hyphen and slash-star forms, string concatenation uses the plus operator, and metadata lives in sys.databases, sys.objects, and INFORMATION_SCHEMA. The attacker confirms by choosing whichever of these T-SQL channels the handler leaves open.

- **Precondition chain:** request input reaches a T-SQL statement on SQL Server, the position is not bound by a typed parameter, and at least one SQL Server channel survives: a CONVERT or CAST error message, a WAITFOR-measurable delay, a stacked-batch effect, or a boolean row-count change.
- **Readable differential:** the same request with a benign literal versus a T-SQL boundary such as a single quote with WAITFOR DELAY or a CAST to int; the response diverges in SQL Server error class, row set, or elapsed seconds, and reverts to baseline when the position is parameterised with a typed parameter.
- **Empirical grounding:** CWE-89 maps to OWASP Top 10:2025 A05:2025 Injection; the dialect behaviour here follows documented T-SQL semantics rather than any single advisory.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed as SQL Server **THEN** start at parent class [`sql-injection`](../sql-injection/SKILL.md) first
2. **IF** SQL Server error text reaches the response **THEN** use a CONVERT or CAST to int error to leak a value in the conversion message, the cheapest SQL Server oracle
3. **IF** no error is reflected but the batch allows a semicolon **THEN** test stacked statements, which T-SQL permits unlike the default MySQL single statement
4. **IF** only timing is observable **THEN** use WAITFOR DELAY with a small interval repeated to clear jitter, since SQL Server has no SLEEP function
5. **IF** the sink is an identifier such as a sort column or a TOP count **THEN** drive the closed-map fix, because bracket quoting does not make an identifier bindable
6. **IF** stacked xp_cmdshell or sp_OACreate appears reachable **THEN** scope impact separately and prove it with a benign echo rather than a command
7. **IF** a WAF blocks the T-SQL probe before the server parses it **THEN** switch to [`sql-injection-waf-tamper-chains`](../sql-injection-waf-tamper-chains/SKILL.md) (1 hop)
8. **IF** the value is stored then concatenated by a later job or report **THEN** switch to [`sql-injection-second-order`](../sql-injection-second-order/SKILL.md) (1 hop)
9. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md)
10. **IF** every value is a typed parameter and identifiers resolve through a server map **THEN** STOP and classify as a verified non-finding for CWE-89

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The sink is an un-bindable identifier such as a sort column or a TOP count | [`sql-injection-orm-and-query-builder`](../sql-injection-orm-and-query-builder/SKILL.md) | Identifiers need a closed map, a different fix from parameterising a value |
| A WAF rejects the T-SQL probe before parsing | [`sql-injection-waf-tamper-chains`](../sql-injection-waf-tamper-chains/SKILL.md) | The invariant moves to parser-differential evasion rather than the database channel |
| The injected value is persisted and run by a later batch | [`sql-injection-second-order`](../sql-injection-second-order/SKILL.md) | The parse happens on a second code path, not at input time |
| Need parent class methodology | [`sql-injection`](../sql-injection/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the T-SQL statement and its parameterisation.** In the data layer, classify each interpolated slot as a bindable value, an un-bindable identifier such as a sort column or TOP count, or a spliced T-SQL fragment.
2. **Pick the SQL Server channel before probing.** Rank CONVERT and CAST error leakage, boolean row-count change, WAITFOR timing, and stacked-batch effect by intrusiveness and choose the least intrusive that can falsify the hypothesis.
3. **Record a paired baseline.** Send two benign literals and capture status, size, and elapsed time; SQL Server report endpoints can be slow, so establish the noise floor before any WAITFOR test.
4. **Define the baseline-versus-probe differential in T-SQL.** For the error channel compare a benign value against a CAST of a subquery to int; for timing compare WAITFOR DELAY of zero against five seconds; the structure, not the data, is the only change.
5. **Branch on the observed channel.** If a conversion error surfaces, stay with CAST and avoid timing; if a semicolon is accepted, note stacked-batch capability but keep probes read-only; if only latency moves, repeat WAITFOR to separate signal from jitter.
6. **Stop condition.** Stop when (a) a T-SQL probe produces a differential that reverts under a typed parameter, (b) no differential appears across two baselines, or (c) advancing would require xp_cmdshell, writes, or exfiltration. Case (a) confirms, (b) is a non-finding, (c) is out of scope for this skill.
7. **State what counts as proof.** Proof is a single-variable T-SQL differential: identical request, one changed literal, a reproducible shift in SQL Server error class such as a conversion error, row count, or WAITFOR-scaled delay, plus the source line where the value or identifier bypasses binding. An unrelated 500 is not proof.
8. **Close with the structural fix.** Bind every value with a typed parameter, replace identifier interpolation with a closed map from token to a bracket-quoted column, and forbid multi-statement batches on the connection; verify by replaying the conversion-error and WAITFOR probes against the patched build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A CONVERT or CAST error echoing a value in its message | Proves the error channel leaks data through type-conversion failures on SQL Server, the cheapest in-band SQL Server oracle |
| A WAITFOR DELAY altering response latency with the injected interval | Proves time-blind injection on SQL Server, which lacks a SLEEP function, and requires a repeated baseline |
| A semicolon-separated second statement taking effect | Proves T-SQL stacked-batch execution, available on SQL Server unlike the default MySQL single statement |
| sys.databases, sys.objects, or INFORMATION_SCHEMA appearing in a response | Proves schema metadata disclosure specific to the SQL Server catalog and reachability of the error or UNION channel |
| @@version or SERVERPROPERTY output in the body | Proves banner disclosure confirming a SQL Server backend; fingerprinting without data extraction |
| An ORDER BY column or TOP count taken from request input | Proves an un-bindable T-SQL identifier slot on SQL Server; bracket quoting does not make it a typed parameter |

## Worked Contrast

**Vulnerable pattern:**

```python
def top_orders(conn, limit, sort):
    # limit and sort are concatenated into T-SQL, so WAITFOR or CONVERT payloads
    # in either slot parse as SQL on SQL Server.
    sql = "SELECT TOP " + limit + " * FROM orders ORDER BY " + sort
    return conn.execute(sql).fetchall()
```

**Hardened pattern:**

```python
SORTABLE = {"created": "[created_at]", "total": "[total_cents]"}

def top_orders(conn, limit, sort):
    try:
        n = int(limit)                 # TOP count is numeric, validated
    except ValueError:
        raise ValueError("limit must be an integer")
    column = SORTABLE.get(sort)        # identifier via closed map, not input
    if column is None:
        raise ValueError("unsortable column")
    sql = "SELECT TOP (?) * FROM orders ORDER BY " + column
    return conn.execute(sql, n).fetchall()
```

**Why this matters:** The hardened version passes the TOP count as a typed parameter and resolves the sort column through a closed map to a bracket-quoted identifier, so neither slot carries attacker T-SQL. WAITFOR and CONVERT payloads can no longer reach the parser because the only variable positions are a bound integer and a server-chosen column name.

## When It Is NOT This Issue

- **Generic 500 with a SQL Server stack trace from bound parameters:** an error page leaking a trace while the statement uses a typed parameter is a configuration finding, not CWE-89.
- **Report endpoint already slow:** a SQL Server report that takes seconds on its own mimics WAITFOR timing, so only a delay scaling with the injected interval and reverting on escaping counts.
- **WAF block page, not a server response:** a 403 vendor page means the T-SQL probe never reached SQL Server, which is a control rather than a safe backend.
- **Bracket-quoted identifier from a closed map:** a sort column looked up server-side and rejected when unknown is safe even though it reaches the T-SQL text.
- **Stacked semicolon rejected by the driver:** some drivers disable multiple statements, so a refused batch is not evidence of injection in a value slot.
- **LINQ or ORM provider mistaken for raw T-SQL:** a provider that never emits SQL Server syntax is out of scope for this dialect skill.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `sql-injection-mssql-variants` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `sql-injection-mssql-variants` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: sql-injection-mssql-variants
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
- [`sql-injection-oracle-variants`](../sql-injection-oracle-variants/SKILL.md) - Web and Application (leaf)
- [`sql-injection-postgres-variants`](../sql-injection-postgres-variants/SKILL.md) - Web and Application (leaf)
- [`sql-injection-sqlite-variants`](../sql-injection-sqlite-variants/SKILL.md) - Web and Application (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `sql-injection-mssql-variants` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-89, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 31 |
| Distinct dataset sources | 6 |
| Top sources | OffsecCyber (13), CYBER_CPT/payloads_all_the_things (13), CYBER_CPT/oxdf (2), CYBER_CPT/github_security_md (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 13 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
