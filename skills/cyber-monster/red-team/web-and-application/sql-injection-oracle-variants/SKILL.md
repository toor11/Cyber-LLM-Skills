---
name: sql-injection-oracle-variants
description: Oracle specific SQL injection. Covers DBMS_PIPE receive_message timing, UTL_HTTP and UTL_INADDR out-of-band exfiltration, dual-table UNION construction, and Oracle error-based and metadata paths. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["oracle injection", "dbms_pipe", "utl_http", "oracle sqli", "dual table"]
cwe: [CWE-89]
owasp: [A03:2021, A05:2025]
attack: [T1190]
capec: [CAPEC-66]
related: [sql-injection, sql-injection-mysql-variants, sql-injection-mssql-variants, sql-injection-postgres-variants]
parent: sql-injection
---

# Sql Injection Oracle Variants - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md)

## Mechanism and Preconditions

Oracle injection is governed by Oracle SQL and PL/SQL idioms. There is no SLEEP, so the reliable time oracle is DBMS_PIPE.RECEIVE_MESSAGE with a timeout; out-of-band uses UTL_HTTP, UTL_INADDR, or DBMS_LDAP because DNS is often less filtered than timing. Every standalone SELECT needs FROM DUAL, and a missing DUAL is the usual reason a probe silently errors. Metadata comes from ALL_TABLES and ALL_TAB_COLUMNS rather than information_schema, UNION requires matching the column count and wrapping non-string columns in TO_CHAR, and the ORA-prefixed errors with two-part object naming fingerprint the backend. Oracle does not support semicolon-stacked batches through standard clients, so escalation runs through functions and UNION rather than stacked statements.

- **Precondition chain:** request input reaches an Oracle SQL statement, the position is not bound, and at least one Oracle channel survives: an ORA-prefixed error leak, ALL_TABLES or ALL_TAB_COLUMNS readability, a DBMS_PIPE-measurable delay, or a UTL_HTTP or UTL_INADDR out-of-band callback.
- **Readable differential:** the same request with a benign literal versus an Oracle boundary such as a quote with DBMS_PIPE.RECEIVE_MESSAGE or a UNION selecting FROM DUAL; the response diverges in the ORA error, rows, or elapsed time, and reverts when the position is bound.
- **Empirical grounding:** CWE-89 maps to OWASP Top 10:2025 A05:2025 Injection; the dialect behaviour here follows documented Oracle SQL and PL/SQL semantics rather than any single advisory.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed as Oracle **THEN** start at parent class [`sql-injection`](../sql-injection/SKILL.md) first
2. **IF** an ORA-prefixed error is reflected **THEN** read the ORA code and two-part object name to confirm Oracle before probing
3. **IF** a standalone SELECT is needed **THEN** append FROM DUAL, since a missing DUAL is the usual reason an Oracle probe silently errors
4. **IF** only timing is observable **THEN** use DBMS_PIPE.RECEIVE_MESSAGE with a timeout, since Oracle has no SLEEP, repeating to clear jitter
5. **IF** no in-band channel survives **THEN** use a UTL_HTTP, UTL_INADDR, or DBMS_LDAP callback to an assessor host, since DNS is usually less filtered
6. **IF** metadata is needed **THEN** enumerate ALL_TABLES and ALL_TAB_COLUMNS, not information_schema which Oracle lacks
7. **IF** a WAF blocks the Oracle probe before parsing **THEN** switch to [`sql-injection-waf-tamper-chains`](../sql-injection-waf-tamper-chains/SKILL.md) (1 hop)
8. **IF** the value is stored then concatenated by a later batch job **THEN** switch to [`sql-injection-second-order`](../sql-injection-second-order/SKILL.md) (1 hop)
9. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md)
10. **IF** every value is a bound variable and identifiers resolve through a server map **THEN** STOP and classify as a verified non-finding for CWE-89

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The sink is an un-bindable identifier such as a sort column | [`sql-injection-orm-and-query-builder`](../sql-injection-orm-and-query-builder/SKILL.md) | Oracle identifiers need a closed map; double-quoting does not bind them |
| A UTL_HTTP or UTL_INADDR callback is the only channel | [`oast-and-blind-vulnerability-testing`](../oast-and-blind-vulnerability-testing/SKILL.md) | Out-of-band confirmation is an OAST oracle discipline distinct from the Oracle grammar |
| A WAF filters DBMS_PIPE or UTL_HTTP before parsing | [`sql-injection-waf-tamper-chains`](../sql-injection-waf-tamper-chains/SKILL.md) | The invariant becomes parser-differential evasion rather than the Oracle channel |
| Need parent class methodology | [`sql-injection`](../sql-injection/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the Oracle statement and its binding boundary.** Classify each interpolated slot as a bind-variable value, an un-bindable double-quoted identifier, or a spliced Oracle fragment, and note whether the query is a standalone SELECT needing FROM DUAL.
2. **Pick the Oracle channel.** Rank ORA error leakage, ALL_TABLES and ALL_TAB_COLUMNS via UNION, DBMS_PIPE.RECEIVE_MESSAGE timing, and UTL_HTTP or UTL_INADDR out-of-band by intrusiveness and pick the least intrusive that falsifies the hypothesis.
3. **Record a paired baseline.** Submit two benign values and note status, length, and timing; since DBMS_PIPE timing is the fallback, establish the jitter floor first.
4. **Define the baseline-versus-probe differential in Oracle syntax.** For UNION compare a benign value against a column-matched UNION selecting FROM DUAL with TO_CHAR casts; for timing compare DBMS_PIPE.RECEIVE_MESSAGE at zero against five; only the structure changes.
5. **Branch on the observed channel.** If ORA text returns, use a benign error probe; if UNION works, enumerate ALL_TABLES; if nothing is in-band, move to a UTL_INADDR DNS callback rather than escalating blind, keeping callbacks to an assessor host.
6. **Stop condition.** Stop when (a) an Oracle probe yields a differential that reverts under a bind variable, (b) no differential appears across two baselines, or (c) advancing would require DBMS_SCHEDULER, Java procedures, or data change. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a single-variable Oracle differential: identical request, one changed literal, a reproducible shift in the ORA error, a row set from DUAL, a DBMS_PIPE-scaled delay, or a callback from the database host, plus the source line that bypasses binding. An ORA-00933 with no attacker control is not proof.
8. **Close with the structural fix.** Bind every value with a named bind variable, replace identifier interpolation with a closed map to a double-quoted column, and remove execute privileges on UTL_HTTP, UTL_INADDR, and DBMS_PIPE from the application schema; verify by replaying the UNION and DBMS_PIPE probes against the patched build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| DBMS_PIPE.RECEIVE_MESSAGE altering response latency | Proves time-blind injection on Oracle, which has no SLEEP, the standard Oracle sleeper needing a repeated baseline |
| UTL_HTTP, UTL_INADDR, or DBMS_LDAP causing an outbound callback | Proves out-of-band extraction on Oracle when no in-band channel survives, where DNS is typically less filtered than HTTP |
| A query requiring FROM DUAL to return a row | Proves an Oracle standalone-SELECT context; a missing DUAL is why many Oracle probes silently error |
| ALL_TABLES or ALL_TAB_COLUMNS appearing in a response | Proves metadata disclosure through the Oracle data dictionary rather than information_schema; UNION or error reachability |
| An ORA-prefixed error with two-part object naming | Proves an Oracle backend and an open error channel; fingerprinting plus potential error-based leakage |
| A double-quoted ORDER BY identifier taken from request input | Proves an un-bindable Oracle identifier slot; double quotes delimit but do not parameterise |

## Worked Contrast

**Vulnerable pattern:**

```python
def report(cur, dept, order):
    # dept and order are concatenated into Oracle SQL, so DBMS_PIPE or a UNION
    # FROM DUAL in dept, or a quoted identifier in order, parse as SQL.
    sql = "SELECT name FROM staff WHERE dept = '" + dept + "' ORDER BY " + order
    cur.execute(sql)
    return cur.fetchall()
```

**Hardened pattern:**

```python
ORDERABLE = {"name": '"NAME"', "hired": '"HIRE_DATE"'}

def report(cur, dept, order):
    column = ORDERABLE.get(order)          # identifier via closed map
    if column is None:
        raise ValueError("unsortable column")
    sql = "SELECT name FROM staff WHERE dept = :dept ORDER BY " + column
    cur.execute(sql, {"dept": dept})       # value bound as a named variable
    return cur.fetchall()
```

**Why this matters:** The hardened query binds the department through a named bind variable, so DBMS_PIPE, UTL_HTTP, and UNION bytes remain data, and resolves the sort column through a closed map to a double-quoted identifier. Because the only variable position is a bind, no Oracle function call or FROM DUAL construction can reach the parser.

## When It Is NOT This Issue

- **An ORA syntax error from bound queries:** an Oracle error while the statement uses bind variables is a handler or logging issue, not CWE-89.
- **UTL_HTTP revoked from the schema:** a callback failing because execute was revoked does not change the in-band finding and is not proof of out-of-band reach.
- **Report already slow:** only a delay scaling with the DBMS_PIPE timeout and reverting on binding counts as timing evidence, not an inherently slow Oracle report.
- **Double-quoted identifier from a closed map:** a sort column resolved server-side and rejected when unknown is safe even though it reaches the text.
- **Missing FROM DUAL causing an error:** an ORA error from a malformed standalone SELECT is a probe mistake, not a confirmed injection.
- **DNS callback from a resolver, not the database host:** a lookup originating from a corporate resolver rather than the database host does not prove the server issued it.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `sql-injection-oracle-variants` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `sql-injection-oracle-variants` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: sql-injection-oracle-variants
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
- [`sql-injection-postgres-variants`](../sql-injection-postgres-variants/SKILL.md) - Web and Application (leaf)
- [`sql-injection-sqlite-variants`](../sql-injection-sqlite-variants/SKILL.md) - Web and Application (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `sql-injection-oracle-variants` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-89, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 11 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/hacktricks (10), OffsecCyber (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 8 det / 0 tools / 2 cases |
| Grounding | multi-dataset corpus-grounded |
