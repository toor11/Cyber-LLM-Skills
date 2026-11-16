---
name: secure-code-review-injection-and-data-flow
description: Injection and data flow review. Covers tracing untrusted input to interpreters, identifying sanitization gaps and confirming exploitability. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: application-security
tier: leaf
triggers: ["code review injection", "taint tracing review", "sink review"]
cwe: [CWE-20]
owasp: []
attack: []
capec: [CAPEC-116]
related: [secure-code-review, secure-code-review-access-control-review, secure-code-review-language-specific-review, threat-modeling]
parent: secure-code-review
---

# Secure Code Review Injection and Data Flow - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Application Security`](../README.md) | Tier: **leaf** | Paired Counterpart: [`sql-injection`](../../../red-team/web-and-application/sql-injection/SKILL.md)

## Mechanism and Preconditions

The injection branch of code review follows data, not keywords: a source (request parameter, header, uploaded file, queue message, third-party response), a propagation path through string building or object copying, and a sink whose interpreter gives the data meaning. The review question is whether the path crosses a transformer that makes the data inert for that specific interpreter. A parameter binding is inert for SQL values but not for identifiers; an HTML escaper is inert for element text but not for a URL attribute.

- **CWE-20 with the relevant child:** CWE-89 for SQL, CWE-78 for OS command, CWE-79 for HTML, CWE-943 for NoSQL operator injection, CWE-502 for deserialisation.
- Inertness is interpreter-specific; a transformer is only a control if it runs on every path to that sink, including error branches.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the sink is a SQL identifier (table, column, `ORDER BY`) **THEN** only a closed allowlist is inert; bound parameters cannot carry identifiers on any driver.
2. **IF** the sink is a template **THEN** distinguish template source from template context; `render_template_string(user_input)` is code execution while `render_template(name, x=user_input)` is not.
3. **IF** the path crosses a language boundary (JSON to shell, YAML to object, HTML to JS) **THEN** check the decoder on the second side, since that is where the meaning is re-interpreted.
4. **IF** the flow is blocked only by client-side validation **THEN** treat it as unblocked; the boundary is the server handler.
5. **IF** the target narrows to `secure-code-review` **THEN** open [`secure-code-review`](../secure-code-review/SKILL.md) for the variant-specific evidence set, because the parent checks here stay too coarse for that profile.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`secure-code-review`](../secure-code-review/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate sources from the framework's request object.** Not grep for `$_GET` but from the actual binding: route parameters, body parsers, multipart fields, headers used in logic, cookies, and message payloads.
2. **Carry each source forward through assignments.** Note every transformation and whether it is encoding, validation, escaping, or merely concatenation. A function named `sanitize` that strips one character class is not a transformer for the sink's grammar.
3. **Choose the branch by sink grammar.** SQL value, SQL identifier, shell argv, shell string, HTML element, HTML attribute, URL, regex, template source, deserialiser, and log line each get their own inert form.
4. **Define the baseline-vs-probe differential.** Baseline: a benign value that must be preserved verbatim in the response or database. Probe: a value that changes behaviour only if the data reached the interpreter (a quote that breaks parsing, a `../`, a `${}`). The finding stands when the probe produces a different class of response than the baseline.
5. **State the stop condition and the proof.** Stop when the sink has a named inert form on every path or the finding is written with the file:line of the sink and the missing transformer; proof is the differential pair plus the code location.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Value concatenated into `ORDER BY` with a `sort` query parameter | Proves identifier injection on any SQL stack; parameters cannot bind an identifier. |
| `subprocess` with `shell=True` and an interpolated filename | Proves shell-string injection on Python; `shell=False` with a list is the inert form. |
| `os.path.join(base, request.args['name'])` used for a file read | Proves path traversal when `..` survives normalisation; the inert form resolves and checks the prefix. |
| MongoDB query built from a JSON body without type checks | Proves operator injection (`{"$ne": null}`) on Node; a schema that pins the field to `string` is the inert form. |

## Worked Contrast

**Vulnerable flow (identifier and shell string built from request data):**

```python
@app.get("/reports")
def reports(sort: str = "id", name: str = ""):
    rows = db.execute(f"SELECT id, total FROM reports ORDER BY {sort}").fetchall()
    size = subprocess.check_output(f"wc -c /srv/reports/{name}", shell=True)
    return {"rows": rows, "size": size.decode()}
```

**Fixed flow (allowlisted identifier, argv list, resolved path):**

```python
_SORT = {"id": "id", "total": "total", "date": "created_at"}
_REPORTS = Path("/srv/reports").resolve()

@app.get("/reports")
def reports(sort: str = "id", name: str = ""):
    col = _SORT.get(sort)
    if col is None:
        raise HTTPException(400, "bad_sort")
    rows = db.execute(f"SELECT id, total FROM reports ORDER BY {col}").fetchall()

    target = (_REPORTS / name).resolve()
    if _REPORTS not in target.parents:
        raise HTTPException(404, "not_found")
    size = subprocess.run(["wc", "-c", str(target)], capture_output=True, check=True).stdout
    return {"rows": rows, "size": size.decode()}
```

**Why this matters:** The first handler lets the caller choose a SQL identifier and a shell fragment, and the path join is irrelevant because the shell already interprets the string. The second maps the identifier through a closed dictionary, passes argv as a list so no shell parses it, and resolves the path to confirm it stays under the report root.

## When It Is NOT This Issue

- **Bound parameter inside a static SQL string.** `WHERE id = %s` with a tuple is inert; do not file because the string looks like SQL.
- **Escaping that matches the sink context.** `html.escape` for element text, `json.dumps` for a JS literal, and `quote()` for a URL path segment are controls; an escaper for the wrong context is not.
- **Deserialisation of data the service itself wrote.** A signed, internal cache entry is not the same finding as a request body; check who can supply the bytes.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `secure-code-review-injection-and-data-flow` based solely on surface keywords (`source to sink`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `secure-code-review-injection-and-data-flow` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: secure-code-review-injection-and-data-flow
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-20`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`sql-injection`](../../../red-team/web-and-application/sql-injection/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`secure-code-review`](../secure-code-review/SKILL.md) - Application Security (flagship)
- [`secure-code-review-access-control-review`](../secure-code-review-access-control-review/SKILL.md) - Application Security (leaf)
- [`secure-code-review-language-specific-review`](../secure-code-review-language-specific-review/SKILL.md) - Application Security (leaf)
- [`threat-modeling`](../threat-modeling/SKILL.md) - Application Security (core)
- [`secure-sdlc-and-security-requirements`](../secure-sdlc-and-security-requirements/SKILL.md) - Application Security (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `secure-code-review-injection-and-data-flow` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/atomic_red_team (6), CYBER_CPT/blackhills (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
