---
name: sql-injection
description: "Tests and exploits SQL injection across every variant: boolean and time-based blind, UNION and error-based extraction, stacked queries, out-of-band exfiltration, second-order injection, and ORM or query-builder sinks. Use when user input reaches a SQL statement, login logic, ORDER BY clause, report filter, or any database-backed parameter."
family: web-and-application
tier: flagship
triggers: ["sql injection", "sqli", "sql inject", "union select", "blind sql", "injection in sql", "database injection"]
cwe: [CWE-89]
owasp: [A03:2021, A05:2025]
attack: [T1190]
capec: [CAPEC-66]
related: [sql-injection-mysql-variants, sql-injection-mssql-variants, sql-injection-oracle-variants, cross-site-scripting]
---

# Sql Injection - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **flagship** | Paired Counterpart: [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md)

## Mechanism and Preconditions

The application assembles a SQL statement by concatenating or interpolating text, so a value intended as data is parsed as SQL grammar by the database. The break happens at the lexical layer: a quote closes the string literal, or an identifier slot in `ORDER BY`, a table name, or a column list accepts an expression the developer never intended as a slot. Parameter binding fixes only the value positions the driver can represent; identifiers, sort direction, `LIMIT` counts, and dialect fragments cannot be bound and must resolve through a closed server-side map. Confirmation therefore depends on which feedback channel the statement leaves open: database error text, row-set shape from a `UNION`, boolean row-count change, measurable delay, or an out-of-band fetch.

- **Precondition chain:** attacker-controlled value or identifier reaches statement text, the driver is not binding that position, and at least one feedback channel survives to the attacker (error text, row count, timing, or an egress path).
- **Readable differential:** same request with a benign literal versus a boundary literal that only changes parse structure; the response must diverge in rows, error class, or elapsed time, and must return to baseline when the boundary character is escaped server-side.
- **Empirical grounding:** CWE-89 covers this class; OWASP Top 10:2025 files injection under A05:2025.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the parameter is bound by the driver in a value position and no identifier slot is interpolated **THEN** classify as a non-finding for CWE-89 and pivot to [`authorization-and-idor`](../authorization-and-idor/SKILL.md) if the concern is row-level access rather than parsing
2. **IF** the sink accepts a sort column, table name, JSON path, or an ID list the builder implodes **THEN** treat the identifier slot as the primary finding and drive the closed-map remediation before testing value payloads
3. **IF** the database is MySQL or MariaDB and the target involves `information_schema`, `SLEEP`, or comment syntax differences **THEN** switch to [`sql-injection-mysql-variants`](../sql-injection-mysql-variants/SKILL.md) (1 hop)
4. **IF** the database is SQL Server and the target involves `WAITFOR`, stacked `;`, or `xp_` procedures **THEN** switch to [`sql-injection-mssql-variants`](../sql-injection-mssql-variants/SKILL.md) (1 hop)
5. **IF** the database is Oracle and the target involves `DUAL`, `UTL_HTTP`, or `ROWNUM` **THEN** switch to [`sql-injection-oracle-variants`](../sql-injection-oracle-variants/SKILL.md) (1 hop)
6. **IF** the database is PostgreSQL and the target involves `pg_sleep`, `COPY`, or `CAST` error leakage **THEN** switch to [`sql-injection-postgres-variants`](../sql-injection-postgres-variants/SKILL.md) (1 hop)
7. **IF** the value is stored cleanly and later concatenated by a different query, job, or report **THEN** switch to [`sql-injection-second-order`](../sql-injection-second-order/SKILL.md) (1 hop)
8. **IF** the sink is an ORM method such as `whereRaw`, `extra`, `order`, a JSON path builder, or a list that is cast only when it is an array **THEN** switch to [`sql-injection-orm-and-query-builder`](../sql-injection-orm-and-query-builder/SKILL.md) (1 hop)
9. **IF** a WAF or filter rejects the probe before the database parses it **THEN** switch to [`sql-injection-waf-tamper-chains`](../sql-injection-waf-tamper-chains/SKILL.md) (1 hop) and keep the probe inside the authorised scope
10. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md)
11. **IF** no reachable sink and no feedback channel remain after inspection **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Sink is a bound value position (`WHERE id = ?`) | [`authorization-and-idor`](../authorization-and-idor/SKILL.md) | Parsing is safe; the remaining risk is row-level authorisation, a different invariant |
| Sink is an identifier slot (sort column, table, JSON path) | [`sql-injection-orm-and-query-builder`](../sql-injection-orm-and-query-builder/SKILL.md) | Identifiers cannot be bound; they need a closed server-side map |
| Value is persisted then concatenated later | [`sql-injection-second-order`](../sql-injection-second-order/SKILL.md) | The parsing happens at the second read, not at input time |
| Target matches `sql-injection-mysql-variants` | [`sql-injection-mysql-variants`](../sql-injection-mysql-variants/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `sql-injection-mssql-variants` | [`sql-injection-mssql-variants`](../sql-injection-mssql-variants/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `sql-injection-oracle-variants` | [`sql-injection-oracle-variants`](../sql-injection-oracle-variants/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `sql-injection-postgres-variants` | [`sql-injection-postgres-variants`](../sql-injection-postgres-variants/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `sql-injection-sqlite-variants` | [`sql-injection-sqlite-variants`](../sql-injection-sqlite-variants/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the statement and its parameterisation boundary.** Read the data access layer, not the controller. Classify every interpolated position as a bindable value, an un-bindable identifier, or a dialect fragment spliced from configuration.
2. **Name the feedback channel before sending anything.** Error text, row-set shape, boolean row count, elapsed time, and out-of-band egress are five different oracles with different blast radii. Choose the least intrusive one that can still falsify the hypothesis: error text first, then row count, then timing, and OAST only when the response is genuinely opaque.
3. **Record a paired baseline.** Send the same request twice with two different benign literals (for example `tenant=a` and `tenant=b`). Any natural variation in length, status, or latency between those two runs is your noise floor; a probe result inside that band is not evidence.
4. **Choose the branch from the observed channel.** If error text is reflected, use a syntax-only probe that cannot return rows. If the row count moves, use a truth-value pair that should return all rows versus none. If only timing is observable, keep the delay small and repeat to separate signal from jitter. If nothing is reflected, move to OAST instead of escalating blind payloads.
5. **Escalate one grammar layer at a time.** Quote behaviour first, then expression context, then stacked statements, then file or network primitives. Stop at the first layer that proves the invariant is missing; the deeper layer only changes impact, not the finding.
6. **Stop condition.** Halt when the probe either (a) produces a differential that reverts when the value is bound or escaped, (b) produces no differential across two independent baselines, or (c) starts to require writing, deleting, or exfiltrating real records. Case (a) is confirmation, (b) is a non-finding, (c) is out of scope for this skill.
7. **State what counts as proof.** Proof is a differential tied to a single variable: identical request, one changed literal, a reproducible change in rows, error class, or elapsed time, plus the exact source line where the identifier or value bypasses binding. A database error string alone is not proof; it must be reachable through attacker-controlled input and disappear when the position is bound.
8. **Close with the structural fix.** Bind every value position; replace identifier interpolation with a closed map from caller token to server-side column; if the ORM exposes a raw fragment, route it through the same map. Verify by re-running the confirmation pair against the patched build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `ORDER BY` column or direction taken from a request parameter | Proves an un-bindable identifier slot on any SQL backend; the parser sees a column expression, not a literal, so the fix is a closed map rather than a bound parameter |
| Database error text naming `information_schema`, `pg_catalog`, or `sysobjects` in an HTTP response | Proves the error channel is open and leaked schema metadata on MySQL, PostgreSQL, or SQL Server; confirms reachability but not extraction |
| Row count or total changing for two literals that should be equivalent | Proves boolean-blind injection where the response body is otherwise stable; the stack is any driver whose result set echoes a count or total |
| Elapsed time proportional to a server-side delay function keyed to the injected literal | Proves time-blind injection on MySQL, PostgreSQL, or SQL Server; requires a repeated baseline because single-sample timing is noise |
| A DNS or HTTP callback arriving from the database host after a probe | Proves out-of-band extraction is possible where no in-band channel survives, typically on hardened production error handling |
| `whereRaw`, `extra`, `order`, or JSON-path builder receiving a request value | Proves the ORM is being used as a string assembler on Laravel, Sequelize, or Knex; the ORM's own escaping does not apply to raw fragments |
| A stored value that appears verbatim inside a later query in an admin report or batch job | Proves second-order injection: input-time validation passes, and the parse failure happens on a different code path |

## Worked Contrast

**Vulnerable Dynamic Value & Identifier Construction:**

```python
def list_orders(cursor, tenant_id: str, sort_col: str, direction: str):
    # String formatting allows breaking out of quotes in WHERE and injecting expressions in ORDER BY
    sql = f"SELECT id, total FROM orders WHERE tenant_id = '{tenant_id}' ORDER BY {sort_col} {direction}"
    cursor.execute(sql)
    return cursor.fetchall()
```

**Fixed Parameterized Values + Closed-Set Identifier Allowlist:**

```python
_ALLOWED_COLS = {"id": "id", "total": "total", "created_at": "created_at"}
_ALLOWED_DIRS = {"asc": "ASC", "desc": "DESC"}

def list_orders(cursor, tenant_id: str, sort_col: str = "created_at", direction: str = "desc"):
    col = _ALLOWED_COLS.get(sort_col)
    dir_sql = _ALLOWED_DIRS.get(direction.lower())
    if col is None or dir_sql is None:
        raise ValueError("Invalid sort specification")
    cursor.execute(f"SELECT id, total FROM orders WHERE tenant_id = %s ORDER BY {col} {dir_sql}", (tenant_id,))
    return cursor.fetchall()
```

**Why this matters:** Bind parameters (`%s`, `?`, `:name`) neutralize data values; SQL identifiers (`ORDER BY`, table/column names) cannot be bound and MUST resolve through a closed server-side dictionary.

## When It Is NOT This Issue

- **Bound value with an echoing error page:** the request returns a database error, but the failing statement uses a bound parameter and the error text comes from a generic handler. A stack trace is a configuration finding, not CWE-89 evidence.
- **Timing that matches an already-slow baseline:** a login or report endpoint that takes seconds on its own will look time-injectable. Only a delay that scales with the injected value, and reverts when the value is escaped, counts.
- **WAF block page mistaken for a database response:** a 403 with a vendor signature means the probe was rejected before parsing. That is a control working, not a vulnerability, and it is not proof of an unfiltered backend either.
- **Identifier already resolved through a closed map:** a sort parameter that is looked up in a server-side dictionary and rejected when absent is safe even though the string reaches the query text.
- **Second-order suspicion with no second query:** a value stored with quotes intact is only a finding if a later code path concatenates it. Locate that path before reporting.
- **Injection into a non-SQL interpreter:** LDAP, XPath, and NoSQL operator injection have their own skills; a `$ne` or `*)(uid=*` probe that works is not SQL injection.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `sql-injection` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `sql-injection` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: sql-injection
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-89 | Mapping: T1190]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md) - Blue Detection/Defense Counterpart
- [`sql-injection-mysql-variants`](../sql-injection-mysql-variants/SKILL.md) - Web and Application (leaf)
- [`sql-injection-mssql-variants`](../sql-injection-mssql-variants/SKILL.md) - Web and Application (leaf)
- [`sql-injection-oracle-variants`](../sql-injection-oracle-variants/SKILL.md) - Web and Application (leaf)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `sql-injection` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-89, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 71 |
| Distinct dataset sources | 13 |
| Top sources | OffsecCyber (26), CYBER_CPT/nuclei_templates (12), hackerone_disclosed_reports (10), cyber-security/security-code (8) |
| Worked contrasts & slot items | 1 inline worked contrast + 1 code / 14 det / 2 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
