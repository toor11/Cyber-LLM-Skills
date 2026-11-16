---
name: secure-code-review-access-control-review
description: Access control review. Covers verifying authorization on every object and function, identifying missing checks and tenant boundaries. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: application-security
tier: leaf
triggers: ["code review access control", "authz review code", "idor code review"]
cwe: [CWE-20]
owasp: []
attack: []
capec: [CAPEC-116]
related: [secure-code-review, secure-code-review-injection-and-data-flow, secure-code-review-language-specific-review, threat-modeling]
parent: secure-code-review
---

# Secure Code Review Access Control Review - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Application Security`](../README.md) | Tier: **leaf** | Paired Counterpart: [`authorization-and-idor`](../../../red-team/web-and-application/authorization-and-idor/SKILL.md)

## Mechanism and Preconditions

Access-control review asks one question per entry point: which predicate decides whether this subject may perform this action on this object, and does it run before the action. Authentication proves a subject exists; authorisation decides the object. The defects that matter are the ones where the predicate is implied by the route (the id came from my session), applied to the collection but not the element, or evaluated against a role the caller can influence. Rails and similar frameworks make this easy to get wrong because scoping helpers are opt-in.

- **CWE-285 / CWE-639:** missing function-level or object-level authorisation; the review distinguishes them because the fixes differ (a role check vs an owner predicate).
- OWASP Top 10:2025 A01 remains the highest-occurrence category and absorbed SSRF; scope this review to authorisation decisions only.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the codebase is Rails with Pundit or CanCanCan **THEN** check `policy_scope` presence on every index action; `authorize` alone covers `show`/`update`, not the collection.
2. **IF** the codebase is DRF **THEN** check `get_object()` usage instead of `Model.objects.get(pk=...)` inside custom actions, since only the former calls `check_object_permissions`.
3. **IF** the finding is tenant isolation specifically **THEN** verify whether the boundary is enforced in the data layer (RLS, schema-per-tenant) before requiring application predicates.
4. **IF** the issue is a role definition rather than a predicate **THEN** route to `privileged-access-management` in the vulnerability family.
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

1. **List actions, not routes.** For each controller or view: index, show, create, update, delete, plus every custom action. Authorisation gaps cluster in the custom ones because scaffolding does not generate them.
2. **Locate the predicate for each action and classify it.** Function-level (role or permission), object-level (owner, tenant, sharing), or field-level (column visibility). Write which one runs and where.
3. **Choose the branch on where scope is derived.** If scope comes from the session or token, check that the query uses it; if it comes from the request body, that is the finding on its own.
4. **Define the baseline-vs-probe differential.** Baseline: owner performs the action. Probe: a second user in the same role, then a user in another tenant, performs the same call with the object id substituted. Identical rejection shapes for foreign and non-existent ids is the pass condition.
5. **State the stop condition and the proof.** Stop when every action has a located predicate and the substitution probe has been replayed per role; proof is the request pair plus the predicate's file:line.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Model.find(params[:id])` in a Rails controller with no `policy_scope` | Proves object-level authorisation is absent on the show path; the session proves identity, not ownership. |
| DRF custom `@action` fetching by `pk` directly | Proves `check_object_permissions` never runs, so a detail route is reachable for any id. |
| Role check reading a claim from the request or a mutable session field | Proves the caller can influence the predicate; role must come from server-side state keyed by the authenticated subject. |
| Index action filtering by a caller-supplied `tenant` parameter | Proves scope comes from the request, which converts a listing endpoint into a cross-tenant read. |

## Worked Contrast

**Vulnerable controller (scaffolded lookup, custom action bypassing the policy):**

```ruby
class InvoicesController < ApplicationController
  def show
    @invoice = Invoice.find(params[:id])          # no policy_scope, no authorize
    render json: @invoice
  end

  def approve
    invoice = Invoice.find(params[:id])           # custom action, same pattern
    invoice.update!(approved: true)
    head :ok
  end
end
```

**Fixed controller (scoped lookup, explicit authorisation on every action):**

```ruby
class InvoicesController < ApplicationController
  def show
    @invoice = policy_scope(Invoice).find(params[:id])
    authorize @invoice, :show?
    render json: @invoice
  end

  def approve
    invoice = policy_scope(Invoice).find(params[:id])
    authorize invoice, :approve?
    invoice.update!(approved: true)
    head :ok
  end
end
```

**Why this matters:** Both actions in the first version resolve the object from the caller's id with no scope and no policy call, so any authenticated user can read or approve any invoice. Scoping the lookup to the policy scope and authorising the specific action means a foreign id and a missing id produce the same not-found path, which also removes the enumeration signal.

## When It Is NOT This Issue

- **Scope enforced by a default_scope or a tenant-aware repository.** A model layer that always appends the tenant predicate is a control even when the controller looks bare; verify the layer.
- **Public-by-design resource.** Marketing pages and published documents are meant to be readable without a predicate; only file the finding when the resource is classified.
- **Admin-only listener behind mTLS and network policy.** If the route is unreachable from untrusted networks, the missing in-app check is defence in depth, not the primary finding.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `secure-code-review-access-control-review` based solely on surface keywords (`object check`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `secure-code-review-access-control-review` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: secure-code-review-access-control-review
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-20`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`authorization-and-idor`](../../../red-team/web-and-application/authorization-and-idor/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`secure-code-review`](../secure-code-review/SKILL.md) - Application Security (flagship)
- [`secure-code-review-injection-and-data-flow`](../secure-code-review-injection-and-data-flow/SKILL.md) - Application Security (leaf)
- [`secure-code-review-language-specific-review`](../secure-code-review-language-specific-review/SKILL.md) - Application Security (leaf)
- [`threat-modeling`](../threat-modeling/SKILL.md) - Application Security (core)
- [`secure-sdlc-and-security-requirements`](../secure-sdlc-and-security-requirements/SKILL.md) - Application Security (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `secure-code-review-access-control-review` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 52 |
| Distinct dataset sources | 2 |
| Top sources | OffsecCyber (32), securecode-web (20) |
| Worked contrasts & slot items | 1 inline worked contrast + 8 code / 0 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
