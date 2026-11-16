---
name: react-nextjs-and-spa-security-architecture
description: "Audits React, Next.js (App Router & Server Actions), and Vue/Angular SPAs: `'use server'` action authentication & Zod input validation, Server-Component `taintUniqueValue`/DTO boundaries preventing secret serialization to RSC payloads, `dangerouslySetInnerHTML` + DOMPurify hooks, and `HttpOnly` BFF token patterns. Use when reviewing modern frontend/fullstack apps."
family: application-security
tier: core
triggers: ["nextjs server actions security", "react rsc data leak", "dangerouslysetinnerhtml", "spa bff auth"]
cwe: [CWE-285, CWE-200]
owasp: [A01:2025]
attack: []
capec: []
related: [secure-code-review, threat-modeling, secure-sdlc-and-security-requirements, secure-design-patterns]
corpus_sparse: true
---

# React Nextjs and Spa Security Architecture - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Application Security`](../README.md) | Tier: **core** | Paired Counterpart: [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

In a Next.js App Router application, every `'use server'` function is a public HTTP endpoint, and every Server Component can read data the browser must never receive. Middleware is a convenience, not an authorisation boundary, and 2026 made that concrete: CVE-2026-64642 bypassed middleware entirely for App Router apps built with Turbopack and a single i18n locale, and CVE-2026-64641 turned Server Actions into a CPU denial of service. The review therefore checks authorisation inside each action and page, the serialisation boundary between server and client, and the sink where model data becomes markup.

- **CWE-285 / CWE-200:** authorisation missing inside an action, and sensitive data crossing the server-client boundary through props or a serialised payload.
- Next.js fixed the July 2026 advisories in 16.2.11 and 15.5.21; the vendor's own workaround is to enforce authorisation in the page's server-side data path rather than relying on middleware.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a file begins with `'use server'` **THEN** treat each exported function as an unauthenticated route: check session, ownership, and input schema inside the function body.
2. **IF** the app relies on middleware for auth **THEN** verify the Next.js version against the 2026 middleware-bypass advisories and move the decision into the page or action.
3. **IF** the concern is token storage or session lifetime **THEN** open `authentication-and-session-design-review`; this skill covers the rendering and boundary side.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **List the endpoints the build actually exposes.** Every Server Action, route handler, and server-side data function, plus `middleware.ts` matchers. CVE-2026-64643 (unauthenticated disclosure of internal Server Function endpoints) means the action ids are discoverable, so obscurity is not a control.
2. **Check the boundary inside each of them.** An action needs the session read server-side, an ownership predicate on the record, and a schema on the input; a page needs the same before it renders, because middleware can be bypassed.
3. **Choose the branch by sink.** Rendered text takes the escaping branch; `dangerouslySetInnerHTML` and markdown rendering take the sanitizer branch; anything returned to a client component takes the serialisation branch (`taintUniqueValue`, DTO projection).
4. **Define the baseline-vs-probe differential.** Baseline: the owner calls the action from the UI. Probe: the same POST replayed with the owner's resource id from a second account, with the action id taken from the build output. The hardened build rejects server-side, not in the client.
5. **State the stop condition and the proof.** Stop when every action and page has an in-body authorisation check and the replay probe fails; proof is the replayed request plus the check's location.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `'use server'` action relying on a layout or middleware guard | Proves authorisation is advisory on Next.js App Router; the action is callable directly as a POST. |
| Sensitive field passed from a Server Component into a client component | Proves the value is serialised into the RSC payload and readable in the browser, even if not rendered. |
| `dangerouslySetInnerHTML` or an unsanitised markdown renderer | Proves stored XSS in a React/Next app; `DOMPurify.sanitize` at the render point is the minimum. |
| Framework below 16.2.11 on App Router with Turbopack and one locale | Proves the CVE-2026-64642 middleware bypass affects that deployment. |

## Worked Contrast

**Vulnerable Next.js Server Action & RSC Boundary (Missing Authz + Secret Serialization + Raw HTML):**

```typescript
'use server'
export async function updateOrgPlan(orgId: string, newPlan: string, bioHtml: string) {
  // BUG 1 (CWE-285): 'use server' creates a public POST endpoint; no session or org-owner check!
  await db.org.update({ where: { id: orgId }, data: { plan: newPlan, bioHtml } });
  // BUG 2 (CWE-200): Returning full DB row leaks stripeSecretKey / internal fields into RSC payload!
  return await db.org.findUnique({ where: { id: orgId } });
}
// Client component renders <div dangerouslySetInnerHTML={{ __html: org.bioHtml }} /> unsanitized!
```

**Hardened Server Action (Session + Zod + Ownership + `taintUniqueValue`/DTO + `DOMPurify`):**

```typescript
'use server'
import DOMPurify from 'isomorphic-dompurify';
import { experimental_taintUniqueValue } from 'react';

const UpdatePlanSchema = z.object({ orgId: z.string().uuid(), newPlan: z.enum(['starter', 'pro']), bioHtml: z.string().max(2000) });

export async function updateOrgPlan(rawInput: unknown) {
  const session = await requireServerSession(); // Auth via HttpOnly BFF session cookie (never localStorage JWT)
  const { orgId, newPlan, bioHtml } = UpdatePlanSchema.parse(rawInput);
  const cleanBio = DOMPurify.sanitize(bioHtml, { ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'] });
  const updated = await db.org.updateMany({
    where: { id: orgId, ownerUserId: session.userId },
    data: { plan: newPlan, bioHtml: cleanBio },
  });
  if (updated.count === 0) throw new Error('Forbidden');
  experimental_taintUniqueValue('Never serialize Stripe key to client RSC', db, process.env.STRIPE_SECRET_KEY!);
  return { orgId, plan: newPlan, bioHtml: cleanBio }; // Minimal public DTO
}
```

**Why this matters:** Every Next.js `'use server'` function is a directly reachable HTTP POST route: enforce HttpOnly BFF session auth, Zod schemas, owner predicates, `DOMPurify.sanitize` before HTML sinks, and `taintUniqueValue` + minimal RSC return DTOs.

## When It Is NOT This Issue

- **Token in `localStorage` on a pure SPA with no server session.** It is a design trade-off, not automatically a finding; the finding is XSS plus that storage, so check the sinks first.
- **Data in a client component that the user is entitled to see.** Server-to-client passing is normal; the finding needs a field the role should not receive.
- **`middleware.ts` doing redirects and locale negotiation.** Non-security middleware is fine; the finding is authorisation that exists only there.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `react-nextjs-and-spa-security-architecture` based solely on surface keywords (`'use server'`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `react-nextjs-and-spa-security-architecture` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: react-nextjs-and-spa-security-architecture
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-285, CWE-200`): [Exact lines/component, broken invariant, reachability, and concrete impact]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `react-nextjs-and-spa-security-architecture` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-285, CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
