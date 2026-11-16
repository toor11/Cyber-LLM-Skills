---
name: graphql-security-batching-and-dos
description: GraphQL batching abuse and denial of service. Covers alias and query batching for brute force, deeply nested and recursive queries, and cost-analysis bypass. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["graphql batching", "graphql dos", "alias brute force", "query depth"]
cwe: [CWE-20]
owasp: [API01:2023, API04:2023]
attack: []
capec: [CAPEC-153]
related: [graphql-security, graphql-security-introspection-and-schema, graphql-security-resolver-authorization, sql-injection]
parent: graphql-security
---

# Graphql Security Batching and Dos - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

A single GraphQL request can demand unbounded server work because one document may alias the same field many times, batch many operations in one array, or nest cyclic relationships that multiply resolver calls geometrically. When the server bounds requests by counting HTTP requests rather than query cost, aliasing also defeats rate limits: one request carries hundreds of labelled attempts at an operation such as an OTP check or a coupon redemption. The security decision is whether the server measures and caps the cost of a query by depth, breadth, alias count, and complexity before resolving it, independent of how many HTTP requests arrive. The attacker crafts one query whose resolved cost far exceeds a normal request. Confirmation is a single request whose measured work or effective attempt count scales with the aliasing or nesting while a baseline request stays flat.

- **Precondition chain:** the endpoint accepts aliased, batched, or deeply nested queries, it enforces no depth, complexity, or alias-count limit before resolution, and either resource consumption or a per-request rate limit can be multiplied inside one document.
- **Readable differential:** a single-field baseline query versus one that aliases or nests the same work many times; a finding exists when measured server work or attempt count scales with the multiplier while the baseline stays flat, and it closes when a cost or depth limit rejects the multiplied query.
- **Empirical grounding:** CWE-20 mapped to OWASP API Security Top 10:2023 API04 unrestricted resource consumption. SOURCES.md has no 2025 CVE specific to GraphQL batching, so this leaf stays grounded at the API04 taxonomy level: query multiplication and alias-based rate-limit bypass as resource-consumption and brute-force amplification.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed to be batching or cost abuse **THEN** start at parent class [`graphql-security`](../graphql-security/SKILL.md) first (1 hop)
2. **IF** the endpoint resolves aliased duplicate fields in one document **THEN** measure whether work scales with the alias count before anything else
3. **IF** a JSON array of operations is processed in one request **THEN** confirm query batching is enabled with two trivial operations
4. **IF** the schema contains cyclic relationships **THEN** test a bounded nested query to see whether depth is limited
5. **IF** aliasing multiplies attempts at a rate-limited operation **THEN** route the single-request brute-force angle to [`race-conditions-and-concurrency-single-packet-attack`](../race-conditions-and-concurrency-single-packet-attack/SKILL.md)
6. **IF** the multiplication bypasses a quota or spend limit **THEN** route the business-limit angle to [`business-logic-flaws-quota-and-rate`](../business-logic-flaws-quota-and-rate/SKILL.md)
7. **IF** aliasing is used to brute-force an OTP or token check **THEN** route the authentication-attempt angle to [`mfa-and-otp-bypass`](../mfa-and-otp-bypass/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** depth, complexity, and alias limits reject multiplied queries and rate limits count operations not requests **THEN** STOP and record a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Aliasing packs many attempts into one request | [`race-conditions-and-concurrency-single-packet-attack`](../race-conditions-and-concurrency-single-packet-attack/SKILL.md) | Invariant is per-attempt limiting, delivered in a single request |
| The multiplier bypasses a spend or usage quota | [`business-logic-flaws-quota-and-rate`](../business-logic-flaws-quota-and-rate/SKILL.md) | Invariant is business quota enforcement, not query cost |
| Aliased attempts brute-force an OTP or token | [`mfa-and-otp-bypass`](../mfa-and-otp-bypass/SKILL.md) | Invariant is attempt throttling on the authentication check |
| Need parent class methodology | [`graphql-security`](../graphql-security/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm which multiplication primitives the endpoint accepts.** Test whether it resolves aliased duplicate fields, processes a JSON array of operations, and follows nested relationships, because the available primitive decides the probe.
2. **Classify the abuse target.** Pure resource consumption, or rate-limit and quota bypass where each aliased field is a separate attempt. Name which, because the proof metric differs between work and attempt count.
3. **Record a single-operation baseline.** Issue one instance of the field or operation and measure its latency, response size, and, for an attempt-based target, that exactly one attempt was consumed.
4. **Scale the multiplier in one request.** Send one document that aliases the field a small, increasing number of times or nests one extra level, holding everything else constant, and measure the same metrics.
5. **Check whether the metric scales with the multiplier.** Compare latency, resolver count, or consumed attempts against the baseline to see whether the server resolved the work without a cap.
6. **Stop condition.** Stop when the multiplied request either (a) shows work or attempt count scaling with the aliasing or nesting while the baseline stayed flat, confirming no cost or per-attempt limit, (b) is rejected by a depth, complexity, or alias limit, or (c) would require driving the multiplier high enough to degrade real service to advance. Case (a) confirms, (b) is a non-finding, (c) is out of scope so keep the multiplier small.
7. **State what counts as proof.** Proof is a single request whose measured cost or effective attempt count rises with the multiplier while an identical-shape baseline stays flat, tied to the alias, batch, or nesting the server resolved uncapped. A slow endpoint that does not scale with the multiplier is not proof.
8. **Separate consumption from rate-limit bypass.** Note whether the impact is server load or a multiplied attempt count against a throttled operation, because the fix differs between cost limiting and per-operation counting.
9. **Close with the structural fix and verify.** Enforce query depth, complexity, and alias-count limits before resolution, count rate limits and quotas per resolved operation rather than per HTTP request, and prefer persisted queries, then replay the multiplied query to confirm rejection.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| One document aliasing the same field many times | Proves alias-based multiplication of work or attempts in a single request |
| A JSON array of operations resolved in one response | Proves query batching is enabled, multiplying operations per request |
| A deeply nested cyclic selection set | Proves recursive relationship expansion that scales resolver calls |
| Latency or resolver count rising with the alias count | Proves the server resolves multiplied work without a cost cap |
| A rate limit that counts HTTP requests rather than operations | Proves aliasing bypasses throttling by packing attempts into one request |
| A depth or complexity limit rejecting the multiplied query | Proves a cost control that closes the consumption surface |
| Persisted-query enforcement rejecting ad hoc documents | Proves the accepted query set is fixed, bounding cost |

## Worked Contrast

**Vulnerable pattern:**

```javascript
// No depth, complexity, or alias limits: one document can multiply work freely
const server = new ApolloServer({ schema });

// Rate limit counts HTTP requests, so aliasing multiplies attempts per request
app.use("/graphql", rateLimit({ windowMs: 60000, max: 10 }), server.getMiddleware());
```

**Hardened pattern:**

```javascript
import depthLimit from "graphql-depth-limit";
import { createComplexityLimitRule } from "graphql-validation-complexity";

const server = new ApolloServer({
  schema,
  validationRules: [depthLimit(6), createComplexityLimitRule(1000)],
});
// Throttle per resolved operation, not per HTTP request
app.use("/graphql", operationRateLimit({ windowMs: 60000, maxOperations: 10 }),
  server.getMiddleware());
```

**Why this matters:** The defective server applies no query-cost limit and throttles by HTTP request, so one aliased or nested document multiplies work and attempts without bound; the fixed server validates depth and complexity before resolving and counts the rate limit per resolved operation, so a multiplied query is rejected and aliasing no longer defeats throttling.

## When It Is NOT This Issue

- **Cost limits enforced:** a server that rejects queries past a depth or complexity bound cannot be multiplied.
- **Per-operation rate limiting:** throttling that counts resolved operations is not bypassed by aliasing within one request.
- **Batching disabled:** an endpoint that refuses operation arrays removes the batch multiplier.
- **No scaling observed:** a multiplied query whose cost does not rise with the multiplier is not a consumption finding.
- **Persisted queries only:** a fixed, pre-registered query set cannot carry arbitrary aliasing or nesting.
- **Idempotent attempt dedup:** an operation that deduplicates repeated attempts in one document defeats alias-based brute force.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `graphql-security-batching-and-dos` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `graphql-security-batching-and-dos` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: graphql-security-batching-and-dos
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-20 | Mapping: API01:2023, API04:2023]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`graphql-security`](../graphql-security/SKILL.md) - Web and Application (core)
- [`graphql-security-introspection-and-schema`](../graphql-security-introspection-and-schema/SKILL.md) - Web and Application (leaf)
- [`graphql-security-resolver-authorization`](../graphql-security-resolver-authorization/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `graphql-security-batching-and-dos` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 17 |
| Distinct dataset sources | 7 |
| Top sources | OffsecCyber (9), SecEval/cwe (2), CYBER_CPT/pstips (2), CYBER_CPT/oxdf (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
