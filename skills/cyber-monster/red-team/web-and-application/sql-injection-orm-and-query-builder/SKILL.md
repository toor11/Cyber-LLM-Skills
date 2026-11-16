---
name: sql-injection-orm-and-query-builder
description: "SQL injection through ORMs and query builders. Covers injection in ORM raw fragments: Hibernate HQL, ActiveRecord where strings, Sequelize literals, Django extra and RawSQL, Prisma raw, and query-builder identifier injection where parameters cannot bind. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology."
family: web-and-application
tier: leaf
triggers: ["orm injection", "hql injection", "active record injection", "django raw", "sequelize literal", "prisma raw", "query-builder identifier injection"]
cwe: [CWE-89]
owasp: [A03:2021, A05:2025]
attack: [T1190]
capec: [CAPEC-66]
related: [sql-injection, sql-injection-mysql-variants, sql-injection-mssql-variants, sql-injection-oracle-variants]
parent: sql-injection
---

# Sql Injection Orm and Query Builder - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md)

## Mechanism and Preconditions

The ORM or query builder escapes only the parameter slots it generates itself; any string handed to a raw-fragment method is spliced into the final SQL text verbatim, so an attacker-supplied ordering clause, JSON path, column name, or raw predicate lands in an identifier position that no bind placeholder can cover. The security decision is whether the fragment is treated as data (bound) or as SQL grammar (concatenated), and it is made inside the builder method, not in the controller. Django `.extra()` and `RawSQL`, Sequelize `sequelize.literal()`, Knex `.whereRaw()` and `.orderByRaw()`, Hibernate `createQuery` HQL concatenation, ActiveRecord string `where`, and Prisma `$queryRawUnsafe` all hand their argument to the driver unescaped. The attacker gains the same grammar break as classic injection, but reached through an API developers assume is safe because the surrounding query is parameterised.

- **Precondition chain:** A request value reaches a raw-fragment builder method such as `whereRaw`, `.extra`, `sequelize.literal`, or `$queryRawUnsafe` or an identifier slot like `order_by`, the builder does not bind that position, and a feedback channel of rows, error, boolean, or timing survives to the caller.
- **Readable differential:** The same builder call with a value the ORM can bind versus a raw fragment carrying a quote or an extra column; a finding exists when the raw path changes rows or raises a driver parse error, and it reverts when the fragment is replaced by a placeholder or a closed column map.
- **Empirical grounding:** CWE-89 sits under OWASP Top 10:2025 A05:2025 Injection. A 2026 instance of identifier-list concatenation is WordPress `WP_Query` `author__not_in` (CVE-2026-60137): `absint` runs only inside `is_array`, and any other shape is imploded into `post_author NOT IN`. `wp_parse_id_list` is the fix, shipped in 6.8.6, 6.9.5, and 7.0.2. On a default install the unauthenticated reachability is the batch route confusion owned by [`cms-and-framework-exploitation-wordpress`](../cms-and-framework-exploitation-wordpress/SKILL.md), not this builder alone.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed to match the ORM raw-fragment case **THEN** start at the parent class [`sql-injection`](../sql-injection/SKILL.md) first (1 hop)
2. **IF** the sink is a bound value position and no raw fragment or identifier slot is interpolated **THEN** classify as a non-finding for CWE-89 and treat residual row-access concerns under [`authorization-and-idor`](../authorization-and-idor/SKILL.md)
3. **IF** the fragment is an ORDER BY or column name reaching `.order_by`, `.orderByRaw`, or a sort builder **THEN** treat the identifier slot as the primary finding and drive a closed column map before any value payload
4. **IF** the builder integer-casts a list only when the value is an array, then implodes the original string **THEN** that is query-builder identifier injection; the WordPress shape is `author__not_in` until `wp_parse_id_list`
5. **IF** the backend behind the ORM is MySQL or MariaDB **THEN** switch to [`sql-injection-mysql-variants`](../sql-injection-mysql-variants/SKILL.md) (1 hop) for the dialect error and delay primitives
6. **IF** the backend behind the ORM is PostgreSQL **THEN** switch to [`sql-injection-postgres-variants`](../sql-injection-postgres-variants/SKILL.md) (1 hop)
7. **IF** the raw value is stored first and concatenated by a later query **THEN** switch to [`sql-injection-second-order`](../sql-injection-second-order/SKILL.md) (1 hop)
8. **IF** a WAF rejects the fragment before the ORM builds the statement **THEN** switch to [`sql-injection-waf-tamper-chains`](../sql-injection-waf-tamper-chains/SKILL.md) (1 hop)
9. **IF** the sink is a document or operator builder such as Mongoose rather than a SQL builder **THEN** reclassify under [`nosql-injection`](../nosql-injection/SKILL.md); operator injection is a different invariant
10. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md)
11. **IF** no raw-fragment method is reachable and every position is bound, including every ID list **THEN** STOP and record a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Fragment is a bound value position the ORM generates | [`authorization-and-idor`](../authorization-and-idor/SKILL.md) | Parsing is safe; the remaining risk is row-level ownership, a different invariant |
| Raw value is persisted then read by another query | [`sql-injection-second-order`](../sql-injection-second-order/SKILL.md) | The parse happens on the second code path, not at the builder call |
| Builder is a document or operator builder | [`nosql-injection`](../nosql-injection/SKILL.md) | The sink is an operator tree, not SQL grammar |
| Need parent class methodology | [`sql-injection`](../sql-injection/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the builder call and classify each argument.** Read the data-access layer and separate bound arguments the ORM generates from strings passed to `whereRaw`, `.extra`, `RawSQL`, `sequelize.literal`, `orderByRaw`, or `$queryRawUnsafe`. Only the raw-fragment arguments and identifier slots are candidate sinks.
2. **Decide whether the position is bindable.** A value in a `WHERE col = ?` slot can bind; an ORDER BY column, a JSON path, a table name, or a spliced predicate cannot. The branch is chosen by the position, not by guessing: if the ORM exposes no placeholder for it, the fragment is grammar.
3. **Record a paired baseline through the builder.** Call the endpoint twice with two benign fragments the API accepts, such as two real sort columns, and read the spread in rows, status, and latency between them as the noise floor for this builder path.
4. **Probe the raw position with a structure-only change.** For an identifier slot send a column token absent from the model; for a raw predicate append a quote or an always-false clause. A driver parse error, an unexpected reorder, or a row-count swing the bound path never produces points to concatenation.
5. **Confirm the escaping gap is the builder, not the controller.** Replace the raw-fragment method with the ORM parameterised equivalent in a local reproduction and re-run the same probe; if the differential disappears, that method was the splice point.
6. **Stop condition.** Halt when the probe yields a differential through the raw method that reverts under a placeholder or closed map, or produces no change across two baselines, or would require writing or reading real rows to progress. The first is confirmation, the second a non-finding, the third out of scope.
7. **State what counts as proof.** Proof is one changed fragment on an otherwise identical builder call producing a reproducible change in rows or a driver parse error, plus the exact source line where `whereRaw`, `RawSQL`, or `orderByRaw` receives request input. ORM auto-escaping elsewhere in the query is not a defence for this position.
8. **Close with the structural fix.** Bind every value position through the ORM placeholder API, and replace identifier interpolation with a server-side map from caller token to an allowlisted column or expression; delete the raw-fragment call where it only concatenated input. Verify by replaying the baseline and probe against the patched builder.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `sequelize.literal()` wrapping a request value | Proves the Sequelize escaper is bypassed because `literal` is spliced verbatim, on a Node and Sequelize stack |
| Django `.extra(where=[...])` or `RawSQL(...)` taking a parameter | Proves the Django ORM treats the fragment as trusted SQL on a Django and Python stack, outside its automatic quoting |
| Knex `.whereRaw()` or `.orderByRaw()` receiving a sort or filter string | Proves the Knex builder concatenates the identifier on Node, where placeholders never cover an ORDER BY column |
| Prisma `$queryRawUnsafe()` called with interpolated input | Proves the unsafe raw escape hatch replaced the tagged `$queryRaw`, on a Prisma and TypeScript stack |
| Hibernate `createQuery` building HQL by string concatenation | Proves HQL grammar injection on a Java and Hibernate stack where positional parameters were available but unused |
| An ORDER BY column or direction sourced from a request parameter in any builder | Proves an un-bindable identifier slot, so the fix is a closed column map rather than a bound parameter |
| ActiveRecord `where` built with string interpolation of params | Proves the Rails string-condition form replaced the array or hash form, on a Ruby and ActiveRecord stack |
| `is_array` then `absint`, else implode of the original string into an `IN` or `NOT IN` list | Proves query-builder identifier injection: the array shape is sanitized and the string shape is concatenated. WordPress `author__not_in` before `wp_parse_id_list` is this shape |

## Worked Contrast

**Vulnerable pattern:**

```python
def list_orders(request):
    # Sort column taken straight from the query string into an identifier slot
    sort = request.GET.get("sort", "created_at")
    # .extra() splices the fragment verbatim; no placeholder covers an ORDER BY column
    return Order.objects.filter(owner=request.user).extra(order_by=[sort])
```

**Hardened pattern:**

```python
SORTABLE = {"created_at": "created_at", "total": "total_cents", "status": "status"}

def list_orders(request):
    token = request.GET.get("sort", "created_at")
    column = SORTABLE.get(token)
    if column is None:
        raise ValueError("unknown sort column")
    # Closed map turns the caller token into a server-chosen column; value filters stay bound
    return Order.objects.filter(owner=request.user).order_by(column)
```

**Why this matters:** The defect is an identifier slot reaching `.extra(order_by=...)`, which no bind placeholder can protect. The fix routes the caller token through a closed server-side map to an allowlisted column and uses the ORM own `order_by`, so an unknown token is rejected instead of concatenated.

## When It Is NOT This Issue

- **Bound value mistaken for raw:** a value in a `filter(id=...)` or `?` slot is escaped by the driver, so a quote that survives in the data is not a parse break.
- **Unknown sort token already rejected:** a sort parameter resolved through a server-side dictionary that raises on a missing key is safe even though the string reached the builder.
- **Raw method over a constant:** `whereRaw` or `literal` wrapping a hard-coded fragment with no request input is a style issue, not CWE-89.
- **ORM error from a type mismatch:** a 500 from passing a string where the model expects an integer is input validation, not grammar injection, if no quote changes the parse tree.
- **Operator injection in a document store:** a Mongoose `$where` or `$ne` payload is NoSQL injection with its own skill, not a SQL builder defect.
- **Second-order splice elsewhere:** a value stored verbatim is only a finding when a later query concatenates it, so locate that query before reporting here.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `sql-injection-orm-and-query-builder` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `sql-injection-orm-and-query-builder` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: sql-injection-orm-and-query-builder
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `sql-injection-orm-and-query-builder` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-89, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 10 |
| Distinct dataset sources | 6 |
| Top sources | SecEval/owasp_wstg (2), CYBER_CPT/L5/ctf_search (2), CYBER_CPT/ctf_search (2), CYBER_CPT/osv (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
