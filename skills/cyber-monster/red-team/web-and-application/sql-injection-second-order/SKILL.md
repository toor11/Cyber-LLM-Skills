---
name: sql-injection-second-order
description: Second-order SQL injection. Covers injection stored by one request and executed by another, including registration-then-password-change flows, admin review screens, and batch jobs that concatenate stored values. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["second order sql", "stored sql injection", "stored injection", "persistent sqli"]
cwe: [CWE-89]
owasp: [A03:2021, A05:2025]
attack: [T1190]
capec: [CAPEC-66]
related: [sql-injection, sql-injection-mysql-variants, sql-injection-mssql-variants, sql-injection-oracle-variants]
parent: sql-injection
---

# Sql Injection Second Order - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md)

## Mechanism and Preconditions

Second-order SQL injection splits the write from the parse: a value passes input-time validation, is stored intact with its quotes, and only becomes SQL when a different code path later concatenates it into a query. The security decision is deferred to that second read, which trusts the database as a clean source and skips the escaping the first endpoint appeared to apply. Typical carriers are a username set at registration and reused in a password-change `WHERE`, a profile field rendered by an admin review screen, or a stored record stitched into a nightly batch or report job. The attacker gains injection on an endpoint that never received the payload directly, which is why input-time testing misses it and why confirmation requires driving the second path.

- **Precondition chain:** A value is stored verbatim without canonicalisation, a later query concatenates that stored value instead of binding it, and that later execution exposes a channel of rows, error, or timing back to someone the attacker can observe.
- **Readable differential:** A stored value that is syntactically inert versus one carrying a quote or predicate, compared after the second code path runs; a finding exists when the deferred query diverges only for the boundary value and reverts when the second read binds the stored value.
- **Empirical grounding:** CWE-89 sits under OWASP Top 10:2025 A05:2025 Injection; SOURCES.md carries no second-order-specific advisory, so this stays at taxonomy level and anchors on the deferred-execution data flow.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed to match the stored-then-executed case **THEN** start at the parent class [`sql-injection`](../sql-injection/SKILL.md) first (1 hop)
2. **IF** the value is bound at both write and read **THEN** classify as a non-finding; the store-then-read path is clean
3. **IF** the suspected second read is an admin review screen **THEN** trigger the finding through that screen with a benign marker before any boundary payload
4. **IF** the second read is a batch or cron job **THEN** account for job cadence in the timing baseline before probing
5. **IF** the stored value is executed on MySQL **THEN** switch to [`sql-injection-mysql-variants`](../sql-injection-mysql-variants/SKILL.md) (1 hop) for the delay and error primitives
6. **IF** the stored value is executed on PostgreSQL **THEN** switch to [`sql-injection-postgres-variants`](../sql-injection-postgres-variants/SKILL.md) (1 hop)
7. **IF** the second read is an ORM raw fragment **THEN** switch to [`sql-injection-orm-and-query-builder`](../sql-injection-orm-and-query-builder/SKILL.md) (1 hop)
8. **IF** the second read produces no in-band signal **THEN** confirm out of band via [`oast-and-blind-vulnerability-testing`](../oast-and-blind-vulnerability-testing/SKILL.md)
9. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md)
10. **IF** no later code path concatenates the stored value **THEN** STOP and record a verified non-finding rather than assuming a second query exists

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Value is bound on the deferred read | [`authorization-and-idor`](../authorization-and-idor/SKILL.md) | Parsing is safe; only who-can-read-what remains, a different invariant |
| Deferred read is a raw ORM fragment | [`sql-injection-orm-and-query-builder`](../sql-injection-orm-and-query-builder/SKILL.md) | The second-path splice is a builder method |
| Second read emits no in-band channel | [`oast-and-blind-vulnerability-testing`](../oast-and-blind-vulnerability-testing/SKILL.md) | Deferred execution is confirmed by out-of-band correlation |
| Need parent class methodology | [`sql-injection`](../sql-injection/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Separate the write endpoint from the read endpoint.** Map where the value enters and is stored through registration, profile update, or import, and every later place that reads it back into a query. The sink is the second path, so inventory reads, not writes.
2. **Classify the stored value handling on the read.** Confirm whether the deferred query binds the stored column or concatenates it; a value pulled from the row and formatted into SQL text is the candidate, a bound column is not.
3. **Plant a benign marker and trace its journey.** Store a harmless unique string, then exercise the suspected read such as an admin screen, report, or job, and confirm the marker appears in that query output or logs. This proves the two paths connect before any boundary test.
4. **Store a structure-only boundary and trigger the read.** Replace the marker with a quote-bearing value, then drive the second path. The differential appears only after the deferred execution, not at write time, which is the signature of this class.
5. **Attribute the timing to the read, not the write.** Because batch and admin reads run later, record the job cadence or screen-load baseline first so a delay is attributed to the deferred query and not to ordinary latency.
6. **Stop condition.** Halt when the deferred read shows a differential that reverts once the stored value is bound on the read, or shows no change after two triggered runs, or would require corrupting real stored records to advance. The first confirms, the second is a non-finding, the third is out of scope.
7. **State what counts as proof.** Proof is a stored value that is inert at write time yet changes rows, error class, or timing when the second path runs, plus the exact later query that concatenates the stored column. A payload that errors at input time is first-order, not this class.
8. **Close with the structural fix.** Bind the stored value on every deferred read and canonicalise at write time as defence in depth, so neither path treats database content as trusted SQL. Verify by re-storing the boundary value and re-triggering the read against the patched build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A username or email set at registration reused in a later `WHERE` by concatenation | Proves the deferred read trusts stored identity values as SQL text on any backend |
| An admin review or moderation screen rendering a stored profile field into a query | Proves a privileged second path parses attacker-stored content, raising impact beyond the attacker own session |
| A nightly batch or report job concatenating stored rows | Proves deferred execution off the request path, where input-time filters never run |
| A value stored with quotes intact and no canonicalisation at write | Proves the write endpoint preserves grammar characters a later query can parse |
| A differential that appears only after a second action, not at submission | Proves the parse is on the read, the defining trait of second-order injection |
| A stored marker surfacing verbatim inside a different query output | Proves the two code paths are connected before any boundary payload |
| A password-change or recovery flow keyed on a stored, concatenated username | Proves a high-value second path that bypasses input-time validation on the recovery endpoint |

## Worked Contrast

**Vulnerable pattern:**

```python
def change_password(cur, session_user, new_hash):
    username = lookup_username(cur, session_user.id)  # stored verbatim at registration
    # Deferred read splices the stored value into SQL text instead of binding it
    sql = "UPDATE users SET pw = '%s' WHERE name = '%s'" % (new_hash, username)
    cur.execute(sql)
```

**Hardened pattern:**

```python
def change_password(cur, session_user, new_hash):
    username = lookup_username(cur, session_user.id)
    # The stored value is bound on the deferred read; database content is never trusted as SQL
    cur.execute("UPDATE users SET pw = %s WHERE name = %s", (new_hash, username))
```

**Why this matters:** The defect treats a stored username as clean and formats it into SQL, so a quote planted at registration parses here even though input-time validation passed. The fix binds the stored value as a parameter on the deferred read, so both the write and the later read treat it as data.

## When It Is NOT This Issue

- **First-order payload that errors at submission:** if the quote breaks the query at write time, it is ordinary injection on the write endpoint, not a second-order finding.
- **Stored value that is bound on read:** a value pulled from the row and passed as a parameter never parses, even with quotes intact.
- **Marker never reaches a second query:** if the planted value does not surface in any later query or output, the two paths are not connected.
- **Write-time canonicalisation strips grammar:** a field normalised to alphanumerics at storage cannot carry a quote into the deferred read.
- **Self-only deferred effect:** a stored payload that only re-parses in the attacker own view, with no admin or batch path, lacks cross-user impact.
- **Reflected echo without execution:** a stored string shown back in HTML is stored XSS territory, not SQL parsing, unless a later query concatenates it.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `sql-injection-second-order` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `sql-injection-second-order` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: sql-injection-second-order
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `sql-injection-second-order` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-89, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 19 |
| Distinct dataset sources | 10 |
| Top sources | OffsecCyber (7), CYBER_CPT/expku (3), hackerone_disclosed_reports (2), SecEval/owasp_wstg (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 9 cases |
| Grounding | multi-dataset corpus-grounded |
