---
name: api-security-review
description: "Reviews API security: authentication and authorization design, object-level access, rate limiting, schema validation and documentation exposure. Use when reviewing or designing APIs."
family: application-security
tier: core
triggers: ["api security review", "api design review", "api authz design"]
cwe: [CWE-20]
owasp: [API01:2023]
attack: []
capec: [CAPEC-116]
related: [secure-code-review, threat-modeling, secure-sdlc-and-security-requirements, secure-design-patterns]
---

# API Security Review - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Application Security`](../README.md) | Tier: **core** | Paired Counterpart: [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md)

## Mechanism and Preconditions

An API review asks three questions per endpoint: who may call it, whose data may it return, and what shape may the request take. The frameworks make all three easy to get wrong in different ways — a router that binds a path parameter into a bare primary-key lookup, a serializer that accepts a nested object graph, a schema document served on the same host. The review is complete when every route in the framework's routing table has an answer for all three, including the routes nobody documented.

- **CWE-20 framing at the API layer:** the defect is a missing predicate or an open schema at a route, not the presence of a JSON body.
- OWASP Top 10:2025 A01 (Broken Access Control) absorbed SSRF and remains first; A02 (Security Misconfiguration) covers exposed schema and debug surfaces.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the API is GraphQL **THEN** check every resolver for its own authorisation before considering field-level rules; a parent guard does not cover a directly addressed node field.
2. **IF** the finding is object-level access on a specific framework (DRF, Spring, Express) **THEN** open that framework's sibling, which names the framework's own object-fetch helper.
3. **IF** the question is rate limiting or quota behaviour under concurrency **THEN** the check belongs with the business-logic and race-condition review, since per-request limits rarely hold across parallel requests.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Export the effective route set.** Include versioned prefixes, feature-flagged routes, internal admin routes, and health or debug endpoints. Compare against the published OpenAPI document; every undocumented route is a review item on its own.
2. **For each route, record the authentication mechanism and the authorisation predicate.** Write them as they execute, not as the annotation reads: middleware order, decorator stacking, and dependency injection all change which one wins.
3. **Choose the branch by object shape.** Path-parameter single objects take the object-level branch; collection endpoints with filters take the property-level branch; bulk and batch endpoints take the per-element check branch.
4. **Define the baseline-vs-probe differential.** Baseline: tenant A reads its own object. Probe: tenant A reads tenant B's id, then a non-existent id. A correct implementation returns the same 404 shape for both, so the probe cannot be used to enumerate existence.
5. **State the stop condition and the proof.** Stop when every route has a recorded predicate and the two-tenant probe has been replayed; proof is the request pair plus the file:line of the predicate, not the API documentation.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `GET /v1/invoices/{id}` resolving the object by primary key only | Proves object-level authorisation is absent on the framework's default fetch; the token proves the caller, not the object. |
| Serializer accepting `tenant_id` or `owner_id` from the body | Proves mass assignment reaches a protected attribute; the write path must derive scope from the token. |
| OpenAPI document served on the production host | Proves an enumeration surface (A02:2025); it is a finding when it exposes internal-only routes, not merely because it exists. |
| Batch endpoint validating the envelope but not each element | Proves a per-element authorisation gap; the envelope check passes because the batch itself is well-formed. |

## Worked Contrast

**Vulnerable handler (envelope-validated batch, per-element scope never applied):**

```typescript
app.post("/v1/invoices/batch", async (req, res) => {
  const items = InvoiceBatch.parse(req.body);            // envelope schema only
  const rows = await db.invoice.findMany({
    where: { id: { in: items.map(i => i.id) } },          // scope from caller's ids
  });
  res.json(rows);
});
```

**Hardened handler (scope derived from the token, per-element result reported):**

```typescript
app.post("/v1/invoices/batch", authenticate, async (req, res) => {
  const items = InvoiceBatch.parse(req.body);
  const rows = await db.invoice.findMany({
    where: { id: { in: items.map(i => i.id) }, tenantId: req.auth.tenantId },
  });
  const byId = new Map(rows.map(r => [r.id, r]));
  res.json(items.map(i => byId.get(i.id) ?? { id: i.id, status: "not_found" }));
});
```

**Why this matters:** The first handler treats a valid envelope as authorisation and returns whatever ids the caller names. The second derives the tenant from the verified token, so the caller's id list can only narrow the result, and the missing elements are reported per item so absence is not an oracle.

## When It Is NOT This Issue

- **Object fetch already scoped by a repository or policy layer.** A `findByIdForTenant` helper or an RLS policy is a predicate even though the handler looks bare; open the helper before filing.
- **Schema document on an internal-only listener.** A spec on a mTLS-protected admin port is not the same finding as one on the public edge; check the listener.
- **404 vs 403 differences that leak nothing.** Returning 404 for both foreign and missing objects is the recommended pattern; do not file the absence of 403 as a defect.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `api-security-review` based solely on surface keywords (`object level authz`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `api-security-review` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: api-security-review
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-20`): [Exact lines/component, broken invariant, reachability, and concrete impact]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `api-security-review` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 30 |
| Distinct dataset sources | 4 |
| Top sources | OffsecCyber (15), hackerone_disclosed_reports (12), cyber-security/security-code (2), bugbounty-hunter-v1 (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
