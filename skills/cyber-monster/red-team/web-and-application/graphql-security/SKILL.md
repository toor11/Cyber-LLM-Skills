---
name: graphql-security
description: "Tests GraphQL APIs: introspection exposure, resolver-level authorization gaps, batching and alias abuse for brute force, nested query DoS, injection through arguments, and federation boundary flaws. Use when an endpoint exposes /graphql or a schema."
family: web-and-application
tier: core
triggers: ["graphql", "graphql introspection", "resolver authz", "query batching", "graphql injection", "graphql dos"]
cwe: [CWE-20]
owasp: [API01:2023, API04:2023]
attack: []
capec: [CAPEC-153]
related: [graphql-security-introspection-and-schema, graphql-security-resolver-authorization, graphql-security-batching-and-dos, sql-injection]
---

# Graphql Security - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **core** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

A GraphQL endpoint exposes one URL whose request body is a typed query the server resolves field by field, so the real attack surface is the schema graph rather than a set of REST routes. Security decisions are distributed across layers that are easy to apply unevenly: introspection exposes the schema, each resolver is responsible for its own authorization, and cost or depth analysis bounds how much work one query can demand. The attacker enumerates the schema, then looks for a field, mutation, or traversal where one of those layers is missing: an unauthorized resolver, an aliased or batched query that multiplies work past a limit, or a nested path that reaches data the UI never exposes. The gain depends on which layer failed; confirmation is a single query that crosses a boundary the server intended to hold, verified against the schema.

- **Precondition chain:** the endpoint accepts GraphQL queries, the schema is recoverable by introspection or error reconstruction, and at least one of resolver authorization, query-cost limiting, or field exposure is applied inconsistently across the graph.
- **Readable differential:** a minimal in-scope query versus one that crosses a suspected boundary such as an unauthorized field, an aliased multiplier, or a hidden mutation; a finding exists when the boundary-crossing query succeeds where the baseline is constrained, and it closes when the responsible layer is enforced uniformly.
- **Empirical grounding:** CWE-20 mapped to OWASP API Security Top 10:2023 API01 (BOLA) and API04 (unrestricted resource consumption). SOURCES.md anchors 2025 resolver-authorization failures: GHSA-cg3c-245w-728m (api-platform Relay `node` field bypassing per-operation security), GHSA-g8jh-vg5j-4h3f (Apollo Router ignoring renamed `@link` access-control directives), and GHSA-x33c-7c2v-mrj9 (Apollo Router applying access control to an interface but not its implementing types).

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target is specifically schema exposure and discovery **THEN** switch to [`graphql-security-introspection-and-schema`](../graphql-security-introspection-and-schema/SKILL.md) (1 hop)
2. **IF** the target is specifically a resolver or field authorization gap **THEN** switch to [`graphql-security-resolver-authorization`](../graphql-security-resolver-authorization/SKILL.md) (1 hop)
3. **IF** the target is specifically batching, aliasing, or query-cost abuse **THEN** switch to [`graphql-security-batching-and-dos`](../graphql-security-batching-and-dos/SKILL.md) (1 hop)
4. **IF** a query argument flows into a database or system call **THEN** route the injection angle to [`nosql-injection`](../nosql-injection/SKILL.md)
5. **IF** the finding is object-level access through a node resolver **THEN** route to [`authorization-and-idor-object-level`](../authorization-and-idor-object-level/SKILL.md)
6. **IF** the same backend is also exposed as REST or gRPC **THEN** compare surfaces via [`rest-and-grpc-api-security`](../rest-and-grpc-api-security/SKILL.md)
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** introspection is controlled, every resolver authorizes independently, and cost limits hold **THEN** STOP and record a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| A node or edge resolver returns another tenant's object | [`authorization-and-idor-object-level`](../authorization-and-idor-object-level/SKILL.md) | Invariant is object-level authorization, framed outside GraphQL syntax |
| The same data is reachable through a REST or gRPC surface | [`rest-and-grpc-api-security`](../rest-and-grpc-api-security/SKILL.md) | Invariant is cross-surface parity of access control |
| A resolver argument reaches a database query operator | [`nosql-injection`](../nosql-injection/SKILL.md) | Invariant is query construction safety, not schema authorization |
| Target matches `graphql-security-introspection-and-schema` | [`graphql-security-introspection-and-schema`](../graphql-security-introspection-and-schema/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `graphql-security-resolver-authorization` | [`graphql-security-resolver-authorization`](../graphql-security-resolver-authorization/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `graphql-security-batching-and-dos` | [`graphql-security-batching-and-dos`](../graphql-security-batching-and-dos/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Recover the schema and locate the endpoint's layers.** Obtain the types, queries, and mutations by introspection or error reconstruction, and identify where authorization, cost analysis, and introspection control are supposed to live.
2. **Classify which layer the task targets.** Schema exposure, resolver authorization, or resource consumption. Each child skill owns one; the parent decides which boundary to test first from the evidence.
3. **Record an in-scope baseline query.** Issue a minimal query the current principal is entitled to and capture the response shape, latency, and depth, so a boundary-crossing query has a reference.
4. **Probe one boundary with a single query.** Select an unauthorized field, an aliased or nested multiplier, or a mutation hidden from the UI, and send exactly one query that crosses that one boundary while holding everything else constant.
5. **Compare against the baseline and the schema.** Confirm whether the response returned data the principal should not see, consumed work past a limit, or executed a hidden operation, cross-checking the schema to prove the field or path was intended to be constrained.
6. **Stop condition.** Stop when the probe either (a) crosses the boundary and returns constrained data, excess work, or a hidden mutation result, (b) is refused by the responsible layer, or (c) would require reading another tenant's real records or degrading service to advance. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a single query that crosses a schema-defined boundary the server meant to hold, tied to the exact field, alias, or mutation and the layer that failed. A successful introspection query alone proves discovery, not a boundary crossing.
8. **Route the confirmed boundary to its child.** Hand schema exposure, resolver authorization, or batching and cost to the matching child for depth and the precise remediation.
9. **Close with the structural fix and verify.** Enforce authorization in every resolver, apply depth and cost limits with persisted queries, and scope introspection to trusted environments, then replay the boundary-crossing query to confirm it is refused.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A single endpoint accepting arbitrary typed queries | Proves the attack surface is the schema graph, not a fixed route set |
| Introspection returning the full type and mutation list | Proves the schema is recoverable, enabling targeted boundary probes |
| A resolver returning an object without checking the caller's entitlement | Proves per-resolver authorization is applied unevenly across the graph |
| Aliased or batched fields multiplying resolver work in one request | Proves a resource-consumption path past per-request limits on API04 |
| A mutation present in the schema but absent from the UI | Proves a hidden operation reachable directly against the endpoint |
| Persisted-query enforcement rejecting ad hoc queries | Proves a control that constrains the accepted query set |
| Depth or cost analysis rejecting a deeply nested query | Proves a consumption limit the batching child would otherwise exploit |

## Worked Contrast

**Vulnerable pattern:**

```javascript
// One endpoint, resolver trusts the argument and returns any user's record
const resolvers = {
  Query: {
    user: (_parent, { id }, _context) => db.users.findById(id),
  },
  Mutation: {
    deleteReport: (_parent, { id }, _context) => db.reports.remove(id),
  },
};
```

**Hardened pattern:**

```javascript
// Every resolver authorizes against the caller in context before returning data
const resolvers = {
  Query: {
    user: (_parent, { id }, ctx) => {
      if (!ctx.user) throw new ForbiddenError("unauthenticated");
      if (ctx.user.id !== id && !ctx.user.isAdmin) throw new ForbiddenError("denied");
      return db.users.findById(id);
    },
  },
  Mutation: {
    deleteReport: (_parent, { id }, ctx) => {
      if (!ctx.user?.isAdmin) throw new ForbiddenError("denied");
      return db.reports.remove(id);
    },
  },
};
```

**Why this matters:** The defective resolvers return and mutate records straight from the argument, so any caller reads another user or deletes a report; the fixed resolvers check the authenticated principal in context against the requested object and the required role before acting, so authorization is enforced at every field rather than assumed at the endpoint.

## When It Is NOT This Issue

- **Uniform resolver authorization:** a graph where every resolver checks entitlement independently has no per-field gap even with introspection on.
- **Introspection in a trusted environment only:** a schema exposed only to authenticated internal users is discovery, not a boundary crossing.
- **Cost and depth limits enforced:** a server that rejects aliased and nested multipliers is not consumption-abusable.
- **Hidden mutation still authorized:** a mutation absent from the UI but gated by the resolver is not reachable by a non-privileged caller.
- **Caller-only data:** a query returning only the caller's own objects is not excessive exposure.
- **Persisted queries only:** an endpoint that accepts only pre-registered queries constrains the whole surface.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `graphql-security` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `graphql-security` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: graphql-security
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-20 | Mapping: API01:2023, API04:2023]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`graphql-security-introspection-and-schema`](../graphql-security-introspection-and-schema/SKILL.md) - Web and Application (leaf)
- [`graphql-security-resolver-authorization`](../graphql-security-resolver-authorization/SKILL.md) - Web and Application (leaf)
- [`graphql-security-batching-and-dos`](../graphql-security-batching-and-dos/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `graphql-security` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 51 |
| Distinct dataset sources | 11 |
| Top sources | OffsecCyber (25), CYBER_CPT/oxdf (14), bugbounty-hunter-v1 (2), SecEval/owasp_wstg (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
