---
name: graphql-security-resolver-authorization
description: GraphQL resolver and field authorization gaps. Covers per-field authorization failures, IDOR through node and edge resolvers, and mutations that trust client-supplied ownership. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["graphql authorization", "resolver authz", "graphql idor", "field authorization"]
cwe: [CWE-20]
owasp: [API01:2023, API04:2023]
attack: []
capec: [CAPEC-153]
related: [graphql-security, graphql-security-introspection-and-schema, graphql-security-batching-and-dos, sql-injection]
parent: graphql-security
---

# Graphql Security Resolver Authorization - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

In GraphQL authorization is the responsibility of each resolver, so a gap appears wherever one resolver returns or mutates data without checking the caller's entitlement even though a sibling resolver does. The classic shapes are a `node(id:)` or edge resolver that fetches any object by identifier regardless of owner, a mutation that trusts a client-supplied ownership field, and a field whose parent was authorized but which itself exposes data the caller should not see. Framework-level shortcuts make this worse: a Relay `node` lookup can bypass per-operation security, access-control directives renamed through `@link` can be silently ignored, and a directive applied to an interface may not cover its implementing types. The security decision is per-resolver, per-object entitlement. Confirmation is one principal retrieving or mutating another principal's object through a resolver that performed no ownership check.

- **Precondition chain:** a resolver returns or mutates an object selected by a client-supplied identifier, that resolver does not check the caller's entitlement to the object, and a sibling operation or the schema shows the object belongs to a different principal.
- **Readable differential:** the same field or mutation requested for the caller's own object versus another principal's identifier; a finding exists when the foreign identifier returns or changes data, and it closes when the resolver authorizes the caller against the object.
- **Empirical grounding:** CWE-20 mapped to OWASP API Security Top 10:2023 API01 (BOLA) and API05 (BFLA). SOURCES.md anchors three distinct 2025 bypasses: GHSA-cg3c-245w-728m (api-platform Relay `node` field bypassing per-operation security), GHSA-g8jh-vg5j-4h3f (Apollo Router ignoring renamed `@link` access-control directives), and GHSA-x33c-7c2v-mrj9 (Apollo Router applying access control to an interface but not its implementing types).

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed to be a resolver authorization gap **THEN** start at parent class [`graphql-security`](../graphql-security/SKILL.md) first (1 hop)
2. **IF** a `node(id:)` or edge resolver fetches objects by identifier **THEN** test a foreign owner's identifier before testing anything else
3. **IF** a mutation accepts a client-supplied ownership or tenant field **THEN** test whether changing that field acts on another principal's object
4. **IF** a Relay `node` lookup may bypass per-operation security **THEN** confirm whether the global node resolver skips the field-level check, as in the api-platform case
5. **IF** access-control directives are imported or renamed through `@link` **THEN** confirm whether the renamed directive is still enforced, as in the Apollo Router case
6. **IF** the finding is better framed as object-level access control **THEN** route to [`authorization-and-idor-object-level`](../authorization-and-idor-object-level/SKILL.md)
7. **IF** the finding is a privileged mutation reachable by a normal user **THEN** route to [`authorization-and-idor-function-level`](../authorization-and-idor-function-level/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** every resolver authorizes the caller against the object and directives cover implementing types **THEN** STOP and record a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| A foreign identifier returns another tenant's object | [`authorization-and-idor-object-level`](../authorization-and-idor-object-level/SKILL.md) | Invariant is object-level ownership, framed outside GraphQL |
| A privileged mutation runs for a normal user | [`authorization-and-idor-function-level`](../authorization-and-idor-function-level/SKILL.md) | Invariant is function-level access to the operation itself |
| An authorized object still exposes a restricted field | [`authorization-and-idor-property-level`](../authorization-and-idor-property-level/SKILL.md) | Invariant is field-level exposure within an allowed object |
| Need parent class methodology | [`graphql-security`](../graphql-security/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Map resolvers that return or mutate objects by identifier.** From the schema, list `node`, edge, and entity-returning fields and every mutation taking an id or ownership argument. These are the authorization decision points.
2. **Classify the authorization shape.** Object read by foreign id, a mutation trusting a client ownership field, a field exposed under an authorized parent, or a framework shortcut (Relay `node`, renamed `@link` directive, interface versus implementation). Each needs a two-account test.
3. **Establish two principals and a self baseline.** With account A, request the target field or mutation for A's own object and record the authorized result. This is the reference the cross-account probe diverges from.
4. **Replay the operation with a foreign identifier.** As account A, request the same field or mutation using account B's object identifier, changing only the id or ownership argument, and observe whether the resolver returns or mutates B's data.
5. **Test the framework shortcuts explicitly.** Reach the object through the global `node` field rather than the typed field, and through any interface type rather than its concrete type, to see whether the per-operation or per-type check is skipped.
6. **Stop condition.** Stop when the cross-account operation either (a) returns or mutates the other principal's object, confirming a missing per-resolver check, (b) is denied identically to an unauthorized request, or (c) would require altering another user's real production data to advance. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is account A receiving or changing account B's object through a specific resolver, evidenced by the two-account differential and the schema showing distinct ownership, plus the resolver or directive that failed to check. A field returning the caller's own object is not proof.
8. **Name the failing control precisely.** State whether it is a missing ownership check, a trusted client field, a bypassed Relay `node`, a renamed ignored directive, or an interface-only directive, because each has a distinct fix.
9. **Close with the structural fix and verify.** Enforce ownership in every resolver against the authenticated context, derive ownership server-side rather than from arguments, and apply access-control directives to implementing types and global `node` lookups, then replay the two-account probe to confirm denial.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A `node(id:)` resolver returning any object by identifier | Proves a global lookup that can skip per-type or per-operation authorization |
| A mutation using a client-supplied owner or tenant field | Proves ownership is taken from the request rather than the authenticated context |
| Account A receiving account B's object through a typed field | Proves a missing per-resolver ownership check, the core BOLA confirmation |
| An access-control directive renamed through `@link` and not enforced | Proves a directive-import gap as in the Apollo Router advisory |
| A directive on an interface absent on its implementing types | Proves polymorphic types escape the interface-level control |
| Resolvers deriving ownership from context and denying foreign ids | Proves per-object authorization is enforced, closing the gap |
| A mutation gated by role before executing | Proves function-level authorization is present on the operation |

## Worked Contrast

**Vulnerable pattern:**

```javascript
// Mutation trusts a client-supplied ownerId and the node resolver skips checks
const resolvers = {
  Query: {
    node: (_p, { id }) => db.findByGlobalId(id),   // any object by id, no owner check
  },
  Mutation: {
    updateProfile: (_p, { ownerId, data }) => db.profiles.update(ownerId, data),
  },
};
```

**Hardened pattern:**

```javascript
const resolvers = {
  Query: {
    node: (_p, { id }, ctx) => {
      const obj = db.findByGlobalId(id);
      if (!ctx.user || obj.ownerId !== ctx.user.id) throw new ForbiddenError("denied");
      return obj;
    },
  },
  Mutation: {
    updateProfile: (_p, { data }, ctx) => {
      if (!ctx.user) throw new ForbiddenError("unauthenticated");
      return db.profiles.update(ctx.user.id, data);   // owner from context, not the arg
    },
  },
};
```

**Why this matters:** The defective resolvers fetch any object through the global `node` id and update whatever `ownerId` the client sends, so one user reaches another's data; the fixed resolvers check the object's owner against the authenticated context and derive the target from the session rather than a client argument, so every resolver enforces per-object ownership.

## When It Is NOT This Issue

- **Ownership from context:** a resolver that derives the owner from the session and denies foreign ids has no BOLA gap.
- **Caller-only object:** a field returning only the caller's own object across two accounts is correctly scoped.
- **Role-gated mutation:** a privileged mutation that checks the role before executing is not a function-level bypass.
- **Directive covers implementations:** an access-control directive applied to both the interface and its implementing types leaves no polymorphic gap.
- **Global node authorized:** a `node` resolver that re-checks entitlement per object is not a shortcut bypass.
- **Shared resource by design:** an object intentionally shared between the two accounts is not unauthorized access.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `graphql-security-resolver-authorization` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `graphql-security-resolver-authorization` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: graphql-security-resolver-authorization
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
- [`graphql-security-batching-and-dos`](../graphql-security-batching-and-dos/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `graphql-security-resolver-authorization` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 3 |
| Distinct dataset sources | 3 |
| Top sources | OffsecCyber (1), CYBER_CPT/pentesterlab (1), CYBER_CPT/ctftime (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 2 cases |
| Grounding | multi-dataset corpus-grounded |
