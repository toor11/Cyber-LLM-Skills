---
name: sql-injection-mysql-variants
description: MySQL and MariaDB specific SQL injection. Covers SLEEP and BENCHMARK timing, information_schema and mysql.innodb_table_stats metadata, LOAD_FILE and INTO OUTFILE file write, stacked queries through PDO multi-statement, and error-based extractvalue and updatexml paths. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["mysql injection", "mariadb injection", "sleep benchmark", "into outfile", "extractvalue"]
cwe: [CWE-89]
owasp: [A03:2021, A05:2025]
attack: [T1190]
capec: [CAPEC-66]
related: [sql-injection, sql-injection-mssql-variants, sql-injection-oracle-variants, sql-injection-postgres-variants]
parent: sql-injection
---

# Sql Injection Mysql Variants - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md)

## Mechanism and Preconditions

On MySQL and MariaDB the confirmation channels are dialect-specific. Timing uses the SLEEP or BENCHMARK functions because WAITFOR does not exist; error-based extraction abuses the XPATH functions extractvalue and updatexml, which embed a subquery result in the error message; metadata is read from information_schema.tables and information_schema.columns. Stacked statements are usually unavailable because the classic client runs one statement per call, so the typical channels are UNION, boolean, time, and error rather than batch. Comments are the double-hyphen form that needs a trailing space, the hash form, and the versioned slash-bang form, identifiers are backtick-quoted, and strings concatenate through the CONCAT function. The attacker picks whichever MySQL channel the handler exposes.

- **Precondition chain:** request input reaches a MySQL or MariaDB statement, the position is not bound by the driver, and at least one MySQL channel survives: an extractvalue or updatexml error, information_schema readability, a SLEEP or BENCHMARK-measurable delay, or a boolean row-count change.
- **Readable differential:** the same request with a benign literal versus a MySQL boundary such as a quote with SLEEP or extractvalue; the response diverges in MySQL error class, rows, or elapsed time, and reverts when the position is bound with a placeholder.
- **Empirical grounding:** CWE-89 maps to OWASP Top 10:2025 A05:2025 Injection; the dialect behaviour here follows documented MySQL and MariaDB semantics rather than any single advisory.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed as MySQL or MariaDB **THEN** start at parent class [`sql-injection`](../sql-injection/SKILL.md) first
2. **IF** a MySQL error is reflected **THEN** use extractvalue or updatexml to leak a value in the XPATH error, the cheapest MySQL in-band oracle
3. **IF** no error surfaces but reads are possible **THEN** read information_schema.tables and information_schema.columns rather than SQL Server catalog views
4. **IF** only timing is observable **THEN** use SLEEP or BENCHMARK since WAITFOR does not exist on MySQL, repeating to clear jitter
5. **IF** the driver has multi-statement execution enabled **THEN** note stacked capability but keep probes read-only, since most MySQL clients run one statement
6. **IF** a comment is needed **THEN** use the double-hyphen with a trailing space, the hash form, or the versioned slash-bang form specific to MySQL
7. **IF** a WAF blocks the MySQL probe before parsing **THEN** switch to [`sql-injection-waf-tamper-chains`](../sql-injection-waf-tamper-chains/SKILL.md) (1 hop)
8. **IF** the ORM exposes a raw fragment such as whereRaw or a raw expression **THEN** switch to [`sql-injection-orm-and-query-builder`](../sql-injection-orm-and-query-builder/SKILL.md) (1 hop)
9. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md)
10. **IF** every value is a bound placeholder and identifiers resolve through a server map **THEN** STOP and classify as a verified non-finding for CWE-89

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The sink is a backtick identifier such as a sort column | [`sql-injection-orm-and-query-builder`](../sql-injection-orm-and-query-builder/SKILL.md) | Backtick quoting does not bind an identifier; it needs a closed map |
| A WAF filters SLEEP or extractvalue before parsing | [`sql-injection-waf-tamper-chains`](../sql-injection-waf-tamper-chains/SKILL.md) | The invariant becomes parser-differential evasion rather than the MySQL channel |
| The value is stored then concatenated by a later report | [`sql-injection-second-order`](../sql-injection-second-order/SKILL.md) | The MySQL parse happens on a second read, not at input time |
| Need parent class methodology | [`sql-injection`](../sql-injection/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the MySQL statement and its binding boundary.** Classify each interpolated slot as a placeholder-bindable value, an un-bindable backtick identifier, or a spliced MySQL fragment.
2. **Pick the MySQL channel.** Rank extractvalue and updatexml error leakage, information_schema readability via UNION, SLEEP and BENCHMARK timing, and boolean row-count change by intrusiveness, choosing the least intrusive that falsifies the hypothesis.
3. **Record a paired baseline.** Send two harmless literals and record status, body size, and latency; because SLEEP timing is the fallback, fix the noise floor first.
4. **Define the baseline-versus-probe differential in MySQL syntax.** For errors compare a benign value against an updatexml wrapping a subquery; for timing compare SLEEP of zero against SLEEP of five; only the parse structure changes.
5. **Branch on the observed channel.** If an XPATH error returns the value, stay with updatexml; if UNION works, enumerate information_schema; if only latency moves, repeat SLEEP to clear jitter; avoid INTO OUTFILE because it writes.
6. **Stop condition.** Stop when (a) a MySQL probe yields a differential that reverts under a bound placeholder, (b) no differential appears across two baselines, or (c) advancing would require LOAD_FILE, INTO OUTFILE, or data change. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a single-variable MySQL differential: identical request, one changed literal, a reproducible shift in a MySQL error such as an XPATH error from updatexml, row count, or SLEEP-scaled delay, plus the source line that bypasses binding. A generic syntax error with no attacker control is not proof.
8. **Close with the structural fix.** Bind every value with a placeholder, replace backtick-identifier interpolation with a closed map, and keep multi-statement execution disabled on the connection; verify by replaying the updatexml and SLEEP probes against the patched build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| extractvalue or updatexml returning a value inside an XPATH error | Proves error-based extraction specific to MySQL and MariaDB XPATH functions, the cheapest in-band MySQL oracle |
| SLEEP or BENCHMARK altering response latency | Proves time-blind injection on MySQL and MariaDB, which lack WAITFOR, and needs a repeated baseline |
| information_schema.tables or information_schema.columns in a response | Proves schema disclosure through the MySQL and MariaDB metadata catalog and reachability of the UNION or error channel |
| A versioned slash-bang comment changing how the statement parses | Proves MySQL-specific versioned-comment handling that can smuggle keywords; MySQL and MariaDB parsers only |
| @@version or @@version_compile_os in the body | Proves a MySQL or MariaDB backend by banner; fingerprinting without extraction |
| A backtick-quoted ORDER BY column taken from request input | Proves an un-bindable MySQL identifier slot; backticks quote but do not parameterise |

## Worked Contrast

**Vulnerable pattern:**

```python
def search(cur, term, order):
    # term and order are concatenated into MySQL text, so updatexml or SLEEP in
    # term, or a backtick identifier in order, parse as SQL.
    sql = "SELECT id,name FROM products WHERE name LIKE '%" + term + "%' ORDER BY " + order
    cur.execute(sql)
    return cur.fetchall()
```

**Hardened pattern:**

```python
ORDERABLE = {"name": "`name`", "price": "`price`"}

def search(cur, term, order):
    column = ORDERABLE.get(order)          # identifier via closed map
    if column is None:
        raise ValueError("unsortable column")
    sql = "SELECT id,name FROM products WHERE name LIKE %s ORDER BY " + column
    cur.execute(sql, ("%" + term + "%",))  # value bound as a placeholder
    return cur.fetchall()
```

**Why this matters:** The hardened query binds the search term as a placeholder, so quote, SLEEP, and extractvalue bytes stay data, and resolves the sort column through a closed map to a backtick-quoted identifier. The LIKE wildcards are added around the bound parameter rather than inside the SQL text, closing both the value and identifier paths.

## When It Is NOT This Issue

- **A MySQL syntax error from bound parameters:** an error surfacing while the statement uses placeholders is a handler or logging issue, not CWE-89.
- **secure_file_priv blocks LOAD_FILE or OUTFILE:** file primitives failing because of server configuration do not change the in-band finding and are not proof of file access.
- **Already-slow endpoint mimicking SLEEP:** only a delay that scales with the SLEEP argument and reverts on binding counts as timing evidence.
- **Backtick identifier from a closed map:** a sort column resolved server-side and rejected when unknown is safe even though it reaches the text.
- **Stacked statement refused:** the classic MySQL client runs one statement, so a rejected second statement is expected and not evidence.
- **Pipe operator behaving as logical OR:** a double-pipe that acts as OR rather than concatenation is normal MySQL mode, not an injection signal.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `sql-injection-mysql-variants` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `sql-injection-mysql-variants` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: sql-injection-mysql-variants
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-89 | Mapping: T1190]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md) - Blue Detection/Defense Counterpart
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`sql-injection-mssql-variants`](../sql-injection-mssql-variants/SKILL.md) - Web and Application (leaf)
- [`sql-injection-oracle-variants`](../sql-injection-oracle-variants/SKILL.md) - Web and Application (leaf)
- [`sql-injection-postgres-variants`](../sql-injection-postgres-variants/SKILL.md) - Web and Application (leaf)
- [`sql-injection-sqlite-variants`](../sql-injection-sqlite-variants/SKILL.md) - Web and Application (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `sql-injection-mysql-variants` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-89, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 22 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/payloads_all_the_things (13), CYBER_CPT/go_exploitdb (3), OffsecCyber (2), CYBER_CPT/osv (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
