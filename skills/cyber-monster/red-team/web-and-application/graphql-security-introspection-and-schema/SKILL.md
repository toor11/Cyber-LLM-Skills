---
name: graphql-security-introspection-and-schema
description: GraphQL introspection and schema analysis. Covers enabling and parsing introspection, reconstructing the schema, and finding fields and mutations hidden from the UI. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["graphql introspection", "graphql schema", "__schema", "graphql discovery"]
cwe: [CWE-20]
owasp: [API01:2023, API04:2023]
attack: []
capec: [CAPEC-153]
related: [graphql-security, graphql-security-resolver-authorization, graphql-security-batching-and-dos, sql-injection]
parent: graphql-security
---

# Graphql Security Introspection and Schema - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

GraphQL servers answer meta-fields such as `__schema` and `__type` that describe every type, field, argument, and mutation, so an enabled introspection query hands the attacker the complete API contract including operations never wired into the UI. When introspection is disabled, the same schema can often be reconstructed from the engine's did-you-mean field suggestions and validation error messages, which leak valid field names one probe at a time. The security decision is whether the schema is a public contract or a controlled asset, and whether error verbosity leaks it indirectly. The attacker uses the recovered schema to prioritise sensitive mutations and hidden fields for later authorization testing. Confirmation is a reconstructed schema fragment, especially a mutation absent from the client, obtained from the endpoint.

- **Precondition chain:** the endpoint answers introspection meta-fields or leaks field names through suggestions and errors, the schema contains operations or fields not exposed in the UI, and the recovered contract is usable to reach those operations.
- **Readable differential:** an introspection or error-reconstruction probe versus a normal client query; a finding exists when the endpoint discloses fields and mutations the client never references, and it closes when introspection is disabled and error messages are generic.
- **Empirical grounding:** CWE-20 under OWASP API Security Top 10:2023 API01 and API04. SOURCES.md has no 2025 CVE specific to GraphQL introspection disclosure, so this leaf stays grounded at the API-security taxonomy level: schema exposure as information disclosure that enables later authorization and resource-consumption testing.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed to be schema exposure **THEN** start at parent class [`graphql-security`](../graphql-security/SKILL.md) first (1 hop)
2. **IF** introspection is enabled and returns the type system **THEN** capture the schema and prioritise sensitive mutations for later authorization testing
3. **IF** introspection is disabled but errors suggest field names **THEN** reconstruct the schema from did-you-mean suggestions one field at a time
4. **IF** the schema reveals mutations hidden from the UI **THEN** route the authorization testing of those mutations to [`graphql-security-resolver-authorization`](../graphql-security-resolver-authorization/SKILL.md)
5. **IF** the schema is recoverable from shipped client JavaScript **THEN** route the bundle-analysis angle to [`web-recon-and-content-discovery-javascript-analysis`](../web-recon-and-content-discovery-javascript-analysis/SKILL.md)
6. **IF** a comparable schema is exposed via OpenAPI or Swagger **THEN** compare the disclosure surface via [`openapi-and-swagger-exposure`](../openapi-and-swagger-exposure/SKILL.md)
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** introspection is disabled and error messages are generic so no hidden field or mutation is recoverable **THEN** STOP and record a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Recovered mutations need authorization testing | [`graphql-security-resolver-authorization`](../graphql-security-resolver-authorization/SKILL.md) | Invariant shifts from disclosure to per-resolver access control |
| The schema is recoverable from client JavaScript bundles | [`web-recon-and-content-discovery-javascript-analysis`](../web-recon-and-content-discovery-javascript-analysis/SKILL.md) | Invariant is client-side exposure of the API contract |
| A REST equivalent exposes its own schema document | [`openapi-and-swagger-exposure`](../openapi-and-swagger-exposure/SKILL.md) | Invariant is specification exposure on a different API style |
| Need parent class methodology | [`graphql-security`](../graphql-security/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Send a standard introspection query and read the result.** Issue the `__schema` meta-query and record whether the server returns the type system or refuses with an introspection-disabled error. The response decides the branch.
2. **Classify the disclosure channel.** Full introspection, partial introspection, or error-and-suggestion reconstruction when introspection is off. Name which channel is open, because each yields the schema at a different rate.
3. **Record a client-known baseline.** List the queries and mutations the official client actually issues, so any field or operation beyond that set is identifiably hidden.
4. **Recover the schema through the open channel.** From full introspection, capture the type and mutation list; from a disabled endpoint, send near-miss field names and harvest the did-you-mean suggestions to rebuild valid names.
5. **Compare the recovered schema to the baseline.** Identify fields, arguments, and mutations present in the schema but absent from the client, especially names suggesting deletion, administration, or payment.
6. **Stop condition.** Stop when the probing either (a) recovers schema elements the client never references, confirming disclosure beyond the intended contract, (b) returns only generic errors and no field names, or (c) would require invoking a recovered sensitive mutation to advance. Case (a) confirms, (b) is a non-finding, (c) belongs to the resolver-authorization child.
7. **State what counts as proof.** Proof is a reconstructed schema fragment, particularly a hidden mutation or field, obtained from the endpoint's introspection or error channel, with the client baseline showing it was never exposed. A schema recovered only from public documentation is not an endpoint disclosure.
8. **Prioritise the recovered surface.** Rank the hidden operations by sensitivity so the authorization child tests the highest-impact mutations first.
9. **Close with the structural fix and verify.** Disable introspection in production, return generic validation errors without field suggestions, and consider persisted queries so the accepted operation set is fixed, then re-run the introspection and suggestion probes to confirm the schema is no longer recoverable.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A `__schema` query returning the full type and mutation list | Proves the API contract is disclosed in one request on this endpoint |
| Did-you-mean field suggestions in validation errors | Proves the schema is reconstructable field by field even with introspection off |
| A mutation in the schema that the official client never issues | Proves a hidden operation exists for later authorization testing |
| `__type` queries enumerating the arguments of a specific type | Proves targeted field and argument disclosure beyond the top-level list |
| Introspection disabled with generic validation errors | Proves the disclosure channels are closed on this server |
| Field-suggestion messages naming adjacent valid fields | Proves verbose errors leak the schema indirectly |

## Worked Contrast

**Vulnerable pattern:**

```javascript
// Introspection on and verbose validation errors leak the schema in production
const server = new ApolloServer({
  schema,
  introspection: true,
  formatError: (err) => err,     // returns did-you-mean field suggestions to clients
});
```

**Hardened pattern:**

```javascript
const isProd = process.env.NODE_ENV === "production";

const server = new ApolloServer({
  schema,
  introspection: !isProd,                      // schema not exposed in production
  formatError: (err) => ({
    message: isProd ? "invalid request" : err.message,   // no field suggestions in prod
  }),
});
```

**Why this matters:** The defective server leaves introspection enabled and returns raw validation errors, so any client downloads the schema or reconstructs it from suggestions; the fixed server disables introspection in production and strips error detail so field names are not suggested, leaving the schema a controlled asset rather than a public contract.

## When It Is NOT This Issue

- **Introspection disabled with generic errors:** neither channel yields field names, so the schema is not recoverable from the endpoint.
- **Schema intentionally public:** a documented public API whose schema is meant to be open is not a disclosure finding.
- **Suggestions off:** an engine configured without did-you-mean messages does not leak field names on near misses.
- **Client-known schema only:** recovering only the operations the UI already issues adds no hidden surface.
- **Persisted queries only:** an endpoint accepting only registered operations makes a recovered schema non-actionable.
- **Public documentation source:** a schema obtained from published docs rather than the endpoint is not an endpoint leak.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `graphql-security-introspection-and-schema` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `graphql-security-introspection-and-schema` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: graphql-security-introspection-and-schema
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-20 | Mapping: API01:2023, API04:2023]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`graphql-security`](../graphql-security/SKILL.md) - Web and Application (core)
- [`graphql-security-resolver-authorization`](../graphql-security-resolver-authorization/SKILL.md) - Web and Application (leaf)
- [`graphql-security-batching-and-dos`](../graphql-security-batching-and-dos/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `graphql-security-introspection-and-schema` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 17 |
| Distinct dataset sources | 6 |
| Top sources | OffsecCyber (8), CYBER_CPT/nuclei_templates (3), SecEval/owasp_wstg (2), CYBER_CPT/osv (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
