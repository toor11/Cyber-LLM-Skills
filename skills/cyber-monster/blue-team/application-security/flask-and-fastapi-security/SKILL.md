---
name: flask-and-fastapi-security
description: "Reviews and hardens Python Flask and FastAPI applications (grounded in securecode-web verified pairs): `Depends()` per-route object-ownership checks, Pydantic strict field allowlists (`extra='forbid'`), Jinja2 autoescape invariants, signed-cookie secret rotation, and SSRF-safe `httpx` wrappers. Use when auditing or building Flask/FastAPI services."
family: application-security
tier: core
triggers: ["fastapi security", "flask security review", "pydantic mass assignment", "depends authz fastapi"]
cwe: [CWE-285, CWE-89, CWE-915]
owasp: [A01:2025, A05:2025]
attack: []
capec: []
related: [secure-code-review, threat-modeling, secure-sdlc-and-security-requirements, secure-design-patterns]
---

# Flask and Fastapi Security - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Application Security`](../README.md) | Tier: **core** | Paired Counterpart: [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md)

## Mechanism and Preconditions

Flask and FastAPI share a dependency-injection idiom and little else. In FastAPI, `Depends()` runs before the handler, so authentication is easy and object authorisation is easy to forget: a `get_current_user` dependency proves who is calling, not which row they may read. In Flask, the request context and `before_request` hooks make the same gap possible in the other direction, since a hook can authenticate while the view fetches by primary key. Pydantic's `extra='forbid'` and Jinja2 autoescaping are the two framework defaults that close the largest classes, and both can be disabled locally by a single line.

- **CWE-285 / CWE-89 / CWE-915:** missing object predicates, identifier interpolation with `text(f"... {col}")`, and `setattr` on a request dict.
- The signed-cookie secret ring is version-gated: Flask reads `SECRET_KEY_FALLBACKS` (3.1+) so old sessions survive rotation; `itsdangerous` exposes the same idea as `fallback_signers`.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the route binds a path id **THEN** check that the query carries `owner_id` or `tenant_id` from the verified principal, not from the body, before anything else.
2. **IF** the framework is Flask with server-rendered templates **THEN** check `render_template_string` and `Markup`/`|safe` usage; autoescaping does not apply to template source.
3. **IF** uploads are involved **THEN** check Werkzeug version, since `safe_join` and `send_from_directory` carried Windows device-name fixes in the 2026 releases.
4. **IF** form or multipart parsing is exposed **THEN** check `python-multipart` and Starlette versions; Starlette below 1.3.1 ignored `max_fields`/`max_part_size` on urlencoded bodies (CVE-2026-54283).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Map dependencies and hooks to guarantees.** For each route, list the dependencies or `before_request` hooks that run and what each one proves. A dependency named `get_current_user` proves identity; only a predicate inside the query proves authorisation.
2. **Read the query construction.** SQLAlchemy `text()` with bound params is inert for values; an f-string around a column name is not. `ORDER BY` and `select` columns need a closed map.
3. **Choose the branch on the write path.** Pydantic models take the `extra='forbid'` branch; Flask form or JSON dicts take the explicit-field-assignment branch; never `setattr` from a request mapping.
4. **Define the baseline-vs-probe differential.** Baseline: the owner reads their invoice. Probe: a second account requests the owner's id, then a non-existent id, then submits `is_admin` in a profile update. The hardened build returns one 404 shape and ignores the extra field.
5. **State the stop condition and the proof.** Stop when every route has a located ownership predicate, every write path has a closed schema, and the probes are replayed; proof is the request pair plus the query or model line.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Depends(get_current_user)` with `db.get(Invoice, inv_id)` | Proves identity without ownership on FastAPI/SQLAlchemy; the dependency never sees the row. |
| `text(f"SELECT ... ORDER BY {sort}")` | Proves identifier injection; a `dict` allowlist is the only inert form for a column name. |
| `for k, v in payload.items(): setattr(user, k, v)` | Proves mass assignment (CWE-915) including `is_admin` and `tenant_id` on either framework. |
| `render_template_string("<h1>" + name + "</h1>")` | Proves template-source injection on Flask, which is code execution rather than XSS. |
| `await request.form()` on Starlette below 1.3.1 with a urlencoded body | Proves the CVE-2026-54283 limit bypass: `max_fields` and `max_part_size` are ignored on that path. |

## Worked Contrast

**Vulnerable Flask/FastAPI Patterns (BOLA + `setattr` Mass Assignment + `ORDER BY` SQLi + `render_template_string` SSTI):**

```python
@router.get("/api/invoices/{inv_id}")
def get_invoice(inv_id: int, name: str = "", db=Depends(get_db), user=Depends(get_current_user)):
    # BUG 1 (SSTI): Concatenating user input into Flask/Jinja2 template source string -> RCE!
    banner = render_template_string("<h1>Invoice for " + name + "</h1>")
    # BUG 2 (BOLA): Bound :id prevents SQLi, but owner_id == user.id is never checked!
    return {"banner": banner, "row": db.execute(text("SELECT * FROM invoices WHERE id = :id"), {"id": inv_id}).first()}

@router.patch("/api/profile")
def patch_profile(raw: dict, sort: str = "id", db=Depends(get_db), user=Depends(get_current_user)):
    for k, v in raw.items():
        setattr(user, k, v)  # BUG 3 (CWE-915): arbitrary ORM attribute write (is_admin/role)
    return db.execute(text(f"SELECT id FROM invoices ORDER BY {sort}")).all()  # BUG 4 (CWE-89): unvalidated identifier
```

**Hardened Flask/FastAPI Patterns (Static Template Context + Scoped Ownership + Strict Pydantic + Identifier Allowlist):**

```python
class ProfilePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display_name: str = Field(min_length=1, max_length=64)

_SORT_COLS = {"id": "id", "created_at": "created_at", "amount": "amount"}

@router.get("/api/invoices/{inv_id}")
def get_invoice(inv_id: int, name: str = "", db=Depends(get_db), user=Depends(get_current_user)):
    banner = render_template("invoice_header.html", name=name)  # Autoescaped template variable, never template source!
    row = db.execute(
        text("SELECT id, amount FROM invoices WHERE id = :id AND owner_id = :uid"),
        {"id": inv_id, "uid": user.id},
    ).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    return {"banner": banner, "row": dict(row)}

@router.patch("/api/profile")
def patch_profile(body: ProfilePatch, sort: str = "id", db=Depends(get_db), user=Depends(get_current_user)):
    user.display_name = body.display_name
    col = _SORT_COLS.get(sort)
    if col is None:
        raise HTTPException(status_code=400, detail="Invalid sort column")
    return db.execute(text(f"SELECT id FROM invoices WHERE owner_id = :uid ORDER BY {col}"), {"uid": user.id}).all()
```

**Why this matters:** Pass untrusted strings as bound template variables (`render_template(..., name=name)` with Jinja2 autoescape), enforce `owner_id == user.id` in queries, restrict writes to `ConfigDict(extra='forbid')` DTOs, and resolve SQL identifiers via closed allowlists.

## When It Is NOT This Issue

- **Framework-level autoescaping plus a static template.** `render_template("x.html", name=name)` is the safe form even though the value is attacker-controlled.
- **Ownership enforced by a repository helper.** `repo.get_for_user(user, id)` is a predicate; read the helper before filing on the bare-looking call site.
- **Pydantic model that already forbids extras.** `model_config = ConfigDict(extra="forbid")` closes the mass-assignment finding for that endpoint; check the model before the handler.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `flask-and-fastapi-security` based solely on surface keywords (`Depends(get_current_user)`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `flask-and-fastapi-security` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: flask-and-fastapi-security
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-285, CWE-89, CWE-915`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`secure-code-review`](../secure-code-review/SKILL.md) - Application Security (flagship)
- [`threat-modeling`](../threat-modeling/SKILL.md) - Application Security (core)
- [`secure-sdlc-and-security-requirements`](../secure-sdlc-and-security-requirements/SKILL.md) - Application Security (core)
- [`secure-design-patterns`](../secure-design-patterns/SKILL.md) - Application Security (core)
- [`secrets-management-and-key-custody`](../secrets-management-and-key-custody/SKILL.md) - Application Security (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `flask-and-fastapi-security` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-285, CWE-89, CWE-915`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 20 |
| Distinct dataset sources | 1 |
| Top sources | securecode-web (20) |
| Worked contrasts & slot items | 1 inline worked contrast + 8 code / 0 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
