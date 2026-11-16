---
name: django-security-patterns
description: "Audits and hardens Django and Django REST Framework (DRF) applications: `QuerySet.extra()`/`RawSQL` pitfalls, DRF `has_object_permission` gotchas on custom `@action` routes, `mark_safe`/`format_html` XSS traps, `ALLOWED_HOSTS`/CSRF cookie settings, and safe `FileField` storage. Use when reviewing Django/DRF codebases."
family: application-security
tier: core
triggers: ["django security", "drf has_object_permission", "mark_safe xss", "rawsql django", "django code review"]
cwe: [CWE-862, CWE-79]
owasp: [A01:2025]
attack: []
capec: []
related: [secure-code-review, threat-modeling, secure-sdlc-and-security-requirements, secure-design-patterns]
---

# Django Security Patterns - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Application Security`](../README.md) | Tier: **core** | Paired Counterpart: [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md)

## Mechanism and Preconditions

Django's defaults are strong where they are explicit - the ORM binds values, the template engine autoescapes, the admin enforces model permissions - and weak exactly where a developer reaches past them: `extra()`/`RawSQL` for an identifier, `mark_safe`/`format_html` around a user value, a DRF custom action that fetches by primary key, and `ModelSerializer` with `__all__`. The review is therefore a diff between what the framework guarantees and what this codebase overrode, plus the settings that switch a guarantee off.

- **CWE-862 / CWE-79 / CWE-89:** missing authorisation on a DRF action, unescaped output where `mark_safe` was used, and identifier interpolation in raw SQL.
- Django's security releases of 3 November 2026 (6.1.3, 6.0.10, 5.2.19) fix CVE-2026-108147, CVE-2026-111211, CVE-2026-111362, CVE-2026-113593, CVE-2026-113733 and CVE-2026-114582, with CVE-2026-111362 (GeoJSON `crs` SSRF) the moderate one.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the endpoint is a DRF `@action` **THEN** check `self.get_object()` rather than `Model.objects.get(pk=pk)`; only the former runs `check_object_permissions` and queryset scoping.
2. **IF** the field is spatial (GeoJSON, `GeometryField`, `SpatialReference`) **THEN** pin Django at or above a release carrying the 2026 SSRF fixes and prefer integer SRIDs over string input.
3. **IF** the concern is authentication or session design rather than per-object authorisation **THEN** open `authentication-and-session-design-review`.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Collect the overrides.** Grep for `RawSQL(`, `extra(`, `mark_safe(`, `format_html(`, `csrf_exempt`, custom `@action`, and `ModelSerializer` classes with `fields = '__all__'` or `exclude`. These are the places where the framework's guarantee no longer applies.
2. **Check each DRF viewset's action set.** Default CRUD routes get scoped querysets automatically; custom actions inherit nothing unless they call `get_object()` or `get_queryset()`. Enumerate them from the router.
3. **Choose the branch on what the override was for.** Raw SQL for performance needs an allowlisted identifier; raw SQL for a value needs a bound parameter; `mark_safe` for trusted markup needs a constant, not a template variable.
4. **Define the baseline-vs-probe differential.** Baseline: owner calls the custom action. Probe: a second user in the same role calls it with the owner's id, and a third call uses a non-existent id. Both must land on the same 404 path; a difference is the finding.
5. **State the stop condition and the proof.** Stop when every override has a named safe form and every custom action has a replayable probe; proof is the DRF route list plus the probe pair.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Custom `@action(detail=True)` fetching by `pk` directly | Proves DRF object permissions never execute, so any authenticated caller reaches any object id on that route. |
| `RawSQL` or `extra(where=...)` with an f-string | Proves the ORM's binding is bypassed for that fragment; identifiers need an allowlist, values still bind. |
| `mark_safe` or `format_html` fed a request value | Proves the autoescape guarantee was removed at that call site on any Django template path. |
| `ModelSerializer` with `__all__` on a model owning `tenant` or `is_staff` | Proves mass assignment can set a protected column through the write endpoint. |
| `GEOSGeometry` or `GeometryField` parsing user GeoJSON carrying a `crs` URL | Proves the CVE-2026-111362 SSRF path on versions below the November 2026 releases. |

## Worked Contrast

**Vulnerable DRF Custom Action + `RawSQL` + `mark_safe`:**

```python
class InvoiceViewSet(ModelViewSet):
    @action(detail=True, methods=["post"])
    def approve(self, request, pk=None):
        # BUG 1: Direct PK lookup skips get_object() -> check_object_permissions() never runs!
        inv = Invoice.objects.get(pk=pk)
        inv.approved = True
        inv.save()
        # BUG 2: RawSQL string formatting + mark_safe on user-controlled memo -> SQLi & XSS
        rows = Invoice.objects.annotate(v=RawSQL(f"SELECT {request.GET['col']}", ()))
        return Response({"badge": mark_safe(f"<span>{inv.memo}</span>"), "count": len(rows)})
```

**Hardened DRF `get_object()` Permission Enforcement + `format_html` + Closed Allowlist:**

```python
_ALLOWED_ANNOTATIONS = {"tax": F("amount") * 0.1, "net": F("amount")}

class InvoiceViewSet(ModelViewSet):
    def get_queryset(self):
        return Invoice.objects.filter(tenant_id=self.request.user.tenant_id)

    @action(detail=True, methods=["post"])
    def approve(self, request, pk=None):
        inv = self.get_object()  # Enforces get_queryset() tenant filter + has_object_permission()
        inv.approved = True
        inv.save(update_fields=["approved"])
        expr = _ALLOWED_ANNOTATIONS.get(request.GET.get("col", "net"))
        if expr is None:
            raise ValidationError("Invalid metric")
        badge = format_html("<span>{}</span>", inv.memo)  # Auto-escapes inv.memo safely
        return Response({"badge": badge, "id": inv.id})
```

**Why this matters:** In DRF `@action(detail=True)`, always call `self.get_object()` so queryset scoping and `has_object_permission` execute, replace `mark_safe(f'...')` with `format_html`, and ban interpolated `RawSQL`/`extra()`.

## When It Is NOT This Issue

- **`format_html` with a constant format string and escaped arguments.** That is the recommended pattern; the finding is only when the format string itself is caller-influenced.
- **`extra()` with no user input in the fragment.** Legacy API use for a static predicate is a modernisation note, not an injection.
- **`csrf_exempt` on a token-authenticated API view.** Exemption is correct when authentication is a bearer token and no cookie is consulted; check the auth class first.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `django-security-patterns` based solely on surface keywords (`check_object_permissions`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `django-security-patterns` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: django-security-patterns
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-862, CWE-79`): [Exact lines/component, broken invariant, reachability, and concrete impact]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `django-security-patterns` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-862, CWE-79`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 20 |
| Distinct dataset sources | 1 |
| Top sources | securecode-web (20) |
| Worked contrasts & slot items | 1 inline worked contrast + 8 code / 0 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
