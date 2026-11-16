---
name: sql-injection-postgres-variants
description: PostgreSQL specific SQL injection. Covers pg_sleep timing, COPY TO PROGRAM and large object escalation, dollar-quoting, and PostgreSQL metadata and error-based paths including current_setting abuse. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["postgres injection", "postgresql sqli", "pg_sleep", "copy to program", "dollar quoting"]
cwe: [CWE-89]
owasp: [A03:2021, A05:2025]
attack: [T1190]
capec: [CAPEC-66]
related: [sql-injection, sql-injection-mysql-variants, sql-injection-mssql-variants, sql-injection-oracle-variants]
parent: sql-injection
---

# Sql Injection Postgres Variants - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md)

## Mechanism and Preconditions

On PostgreSQL the parser distinguishes a single-quoted string literal, a double-quoted identifier, and a dollar-quoted block, so a value that escapes its single-quote context is read as SQL and an identifier spliced without a server-side map lands in a double-quote slot no bind can cover. Postgres leaks through its own surfaces: SQLSTATE 42601 for syntax, 42703 for an undefined column, and especially the cast error `invalid input syntax for type integer`, which echoes the offending value back. Blind confirmation uses `pg_sleep()` for timing and ordinary boolean predicates for row-count differentials, while schema metadata lives in `pg_catalog` and `pg_tables` rather than in `information_schema` alone. High-impact primitives such as `COPY ... TO PROGRAM`, large objects, and `current_setting` exist only when the role is privileged, so the finding is the grammar break and the impact is bounded by that role.

- **Precondition chain:** A request value reaches a Postgres statement in a single-quote, double-quote, or dollar-quoted position, the driver does not bind that position, and at least one Postgres channel survives such as a 42601 or 42703 state, a cast error, a boolean row swing, or a `pg_sleep` delay.
- **Readable differential:** The same request with a benign literal versus one that closes the quote or forces a cast error; a finding exists when the response diverges in rows, a Postgres SQLSTATE, or a `pg_sleep`-keyed delay, and it reverts when the value is bound.
- **Empirical grounding:** CWE-89 sits under OWASP Top 10:2025 A05:2025 Injection; SOURCES.md carries no PostgreSQL-specific SQL advisory, so this stays at taxonomy level while naming the dialect error states and primitives.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed to match the PostgreSQL case **THEN** start at the parent class [`sql-injection`](../sql-injection/SKILL.md) first (1 hop)
2. **IF** the value sits in a bound `$1` placeholder and no identifier is interpolated **THEN** classify as a non-finding and consider [`authorization-and-idor`](../authorization-and-idor/SKILL.md) for row access
3. **IF** the error surface echoes a cast message like invalid input syntax for type integer **THEN** drive error-based confirmation from the cast channel before timing
4. **IF** only timing is observable **THEN** use a bounded `pg_sleep` pair and repeat to clear jitter
5. **IF** the backend is actually MySQL or MariaDB **THEN** switch to [`sql-injection-mysql-variants`](../sql-injection-mysql-variants/SKILL.md) (1 hop)
6. **IF** the sink is an ORM raw fragment such as Django RawSQL or Knex orderByRaw **THEN** switch to [`sql-injection-orm-and-query-builder`](../sql-injection-orm-and-query-builder/SKILL.md) (1 hop)
7. **IF** no in-band channel survives but egress is open **THEN** confirm out of band via [`oast-and-blind-vulnerability-testing`](../oast-and-blind-vulnerability-testing/SKILL.md)
8. **IF** a WAF blocks the quote before Postgres parses it **THEN** switch to [`sql-injection-waf-tamper-chains`](../sql-injection-waf-tamper-chains/SKILL.md) (1 hop)
9. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md)
10. **IF** no reachable sink and no Postgres channel remain after inspection **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Value is bound in a `$1` parameter | [`authorization-and-idor`](../authorization-and-idor/SKILL.md) | Parsing is safe; only row-level authorisation remains, a different invariant |
| Raw fragment reaches a Postgres statement via an ORM | [`sql-injection-orm-and-query-builder`](../sql-injection-orm-and-query-builder/SKILL.md) | The splice point is the builder method, not hand-written SQL |
| No in-band channel, only an egress callback | [`oast-and-blind-vulnerability-testing`](../oast-and-blind-vulnerability-testing/SKILL.md) | Confirmation moves to out-of-band correlation, a different oracle |
| Need parent class methodology | [`sql-injection`](../sql-injection/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the Postgres statement and classify the quote context.** Read the query text and mark whether the request value sits inside a single-quoted literal, a double-quoted identifier, or a dollar-quoted `$$` block, and whether the driver uses a `$1` placeholder for it.
2. **Pick the Postgres channel from the observed error surface.** A reflected `invalid input syntax for type integer` points to the cast channel, a 42601 to the syntax channel, a stable body with a changing total to boolean, and silence to `pg_sleep` timing. Choose the least intrusive one that can falsify the hypothesis.
3. **Capture a two-literal baseline.** Issue the request twice with two benign literals and note the row count, any SQLSTATE, and the elapsed time; that spread is the Postgres noise floor before any probe.
4. **Probe the quote boundary without returning data.** For a literal context append a single quote and an always-false clause; for an integer context force a cast mismatch to trigger the echoing error. The branch follows the context you classified, not a blind payload sweep.
5. **Escalate one Postgres layer at a time.** Move from quote behaviour to boolean predicates to a bounded `pg_sleep`, and only name `COPY ... TO PROGRAM`, large objects, or `current_setting` as impact once the role is shown privileged; the deeper primitive changes severity, not the finding.
6. **Stop condition.** Halt when the probe produces a Postgres differential that reverts under a bound `$1`, or shows no change across two baselines, or would require reading real `pg_catalog` data or invoking `COPY TO PROGRAM`. The first confirms, the second is a non-finding, the third is out of scope.
7. **State what counts as proof.** Proof is one changed literal on an identical request yielding a reproducible move in rows, a specific SQLSTATE such as 42601 or 42703, or a `pg_sleep` delay above the baseline spread, plus the source line where the value is concatenated rather than bound. A bare Postgres error page without input control is not proof.
8. **Close with the structural fix.** Bind every literal with `$1` parameters, quote identifiers only from a server-side allowlist, and run the application role with least privilege so `COPY`, large objects, and superuser settings are unreachable. Verify by replaying the cast and boolean probes against the patched build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `invalid input syntax for type integer` reflected in the response | Proves the Postgres cast channel is open and echoes the injected value on a PostgreSQL backend |
| SQLSTATE 42601 syntax error tied to an injected quote | Proves the lexer reached attacker input on PostgreSQL, a state a bound parameter would never surface |
| SQLSTATE 42703 undefined column from a sort or column token | Proves an identifier slot is interpolated on PostgreSQL rather than mapped server-side |
| Elapsed time tracking a `pg_sleep()` argument | Proves time-blind injection on PostgreSQL, which needs repeats because a single `pg_sleep` sample resembles load |
| A dollar-quoted `$$` sequence changing how the statement parses | Proves the value escaped standard quote handling through Postgres dollar-quoting, unique to this dialect |
| `pg_catalog` or `pg_tables` names appearing in responses or logs | Proves schema enumeration through Postgres catalog views where the normal query never references them |
| `current_setting(` or `COPY ... TO PROGRAM` reachable in the statement | Proves a privileged primitive is in grammar reach on PostgreSQL, with impact bounded by the role rights |

## Worked Contrast

**Vulnerable pattern:**

```python
def search_orders(cur, request):
    status = request.GET.get("status", "open")
    # Value concatenated into a single-quote literal on PostgreSQL
    cur.execute("SELECT id, total FROM orders WHERE status = '%s'" % status)
    return cur.fetchall()
```

**Hardened pattern:**

```python
def search_orders(cur, request):
    status = request.GET.get("status", "open")
    # psycopg2 binds the value as a $1 parameter; the quote context belongs to the driver
    cur.execute("SELECT id, total FROM orders WHERE status = %s", (status,))
    return cur.fetchall()
```

**Why this matters:** The defect uses Python formatting to place the value inside a single-quoted literal, so a quote re-opens Postgres grammar and the cast or 42601 channel leaks. The fix passes the value as a bound parameter tuple, so psycopg2 owns the quoting and the same input is data, not SQL.

## When It Is NOT This Issue

- **Generic Postgres error page:** a 500 showing a stack trace from a bound query is a configuration leak, not CWE-89; the value must change the parse tree.
- **Slow report mistaken for pg_sleep:** an endpoint already taking seconds looks time-injectable, so only a delay that scales with the `pg_sleep` argument and reverts when bound counts.
- **COPY TO PROGRAM denied by role:** the grammar may reach `COPY`, but an unprivileged role cannot execute it, so report the injection, not unproven command execution.
- **Cast error from legitimate bad input:** an `invalid input syntax` raised by an honestly non-numeric value is input validation unless a quote or expression alters parsing.
- **Catalog reference in normal code:** some ORMs query catalogs during migrations, so a `pg_catalog` hit outside request flow is not evidence of enumeration.
- **Dollar-quoted block in a function body:** `$$` inside a legitimate function definition is ordinary Postgres syntax, not an injected escape.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `sql-injection-postgres-variants` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `sql-injection-postgres-variants` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: sql-injection-postgres-variants
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
- [`sql-injection-sqlite-variants`](../sql-injection-sqlite-variants/SKILL.md) - Web and Application (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `sql-injection-postgres-variants` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-89, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 3 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/oxdf (1), CYBER_CPT/ctftime (1), CYBER_CPT/go_exploitdb (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 3 cases |
| Grounding | multi-dataset corpus-grounded |
