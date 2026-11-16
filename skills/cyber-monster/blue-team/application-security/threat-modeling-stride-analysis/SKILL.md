---
name: threat-modeling-stride-analysis
description: STRIDE analysis. Covers applying STRIDE per element and trust boundary, producing concrete threats rather than generic lists. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: application-security
tier: leaf
triggers: ["stride threat model", "stride analysis"]
cwe: [CWE-20]
owasp: []
attack: []
capec: [CAPEC-116]
related: [threat-modeling, threat-modeling-attack-tree-and-misuse-cases, secure-code-review, secure-sdlc-and-security-requirements]
parent: threat-modeling
---

# Threat Modeling Stride Analysis - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Application Security`](../README.md) | Tier: **leaf** | Paired Counterpart: [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md)

## Mechanism and Preconditions

STRIDE per element is a completeness device: for each element on the diagram you ask the six questions and record either a threat or an explicit reason there is none. The value is that the grid is exhaustive and repeatable, so two reviewers reach the same coverage; the risk is turning it into a table nobody acts on. Keep the artefact small - one row per element-and-category that produced a credible threat, with the control that would have to fail and where it lives.

- **Six categories, one meaning each:** Spoofing (identity), Tampering (integrity of data in transit or at rest), Repudiation (missing evidence), Information disclosure (confidentiality), Denial of service (availability), Elevation of privilege (authorisation).
- A category with no threat is a finding too: record why it does not apply to that element.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the request starts from adversary goals rather than element categories **THEN** use `threat-modeling-attack-tree-and-misuse-cases`, which decomposes goals instead.
2. **IF** the diagram does not exist **THEN** produce it with `threat-modeling` first; a STRIDE grid without boundaries is a list of nouns.
3. **IF** a threat turns into a concrete test **THEN** hand it to `purple-teaming-and-adversary-emulation-technique-selection` so it becomes a validated technique.
4. **IF** the target narrows to `threat-modeling` **THEN** open [`threat-modeling`](../threat-modeling/SKILL.md) for the variant-specific evidence set, because the parent checks here stay too coarse for that profile.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`threat-modeling`](../threat-modeling/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Fix the element list from the diagram.** Processes, data stores, data flows, external entities, and trust boundaries. Every flow crosses at least one boundary or the diagram is wrong.
2. **For each element, walk the six categories in a fixed order.** Write the threat in one sentence naming the element, the abuse, and the consequence. Skip nothing silently; write 'not applicable because ...' where it does not hold.
3. **Choose the branch per surviving row.** Spoofing and elevation rows take the authentication and authorisation branch; tampering and information disclosure take the integrity and encoding branch; repudiation takes the logging branch; denial of service takes the quota branch.
4. **Define the baseline-vs-probe differential per row.** Baseline: the legitimate flow through that element. Probe: the substitution the threat describes. A row is credible only when you can name the observable that would differ.
5. **State the stop condition and the proof.** Stop when every element has six dispositions, every surviving threat has a located control or an accepted-risk id, and the grid is versioned with the diagram; proof is the grid plus the control locations.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Spoofing row on a data flow with mTLS and SPIFFE identity | Proves the control exists at the transport layer, so the residual threat is credential theft rather than impersonation. |
| Tampering row on a client-supplied total | Proves server-side recomputation is the control; the row is credible when the price table is the authority and the client value is decorative. |
| Repudiation row on an action with no audit event | Proves an evidence gap; the control is the decision event, not an application log line. |
| Elevation row on an admin route reachable from the user tier | Proves a boundary crossing without authorisation; the row is the finding, the control is a tier-separated listener. |

## Worked Contrast

**STRIDE grid used as a checklist (rows with no control location):**

```text
Element            S  T  I  D  E  R
Browser            -  -  -  -  -  -
Web tier           X  X  -  X  -  -
API                -  X  X  -  X  -
Database           -  -  X  -  -  -
Notes: reviewed in workshop, actions to follow
```

**STRIDE grid with dispositions and located controls:**

```text
Element: API process
S Spoofing        -> threat: stolen bearer token replayed
                     control: 120s access token, sender-constrained refresh (DPoP)
                     where:   auth/tokens.go:64 verifyBinding()
T Tampering       -> threat: caller rewrites amount_minor
                     control: recompute from order_id price table
                     where:   handlers/charge.py:88
I Info disclosure -> threat: error body carries SQL text
                     control: generic error envelope in prod profile
                     where:   middleware/errors.go:31
D DoS             -> threat: 50MB JSON body
                     control: MaxBytesReader 1MB + 10s write timeout
                     where:   server.go:22
E Elevation       -> threat: none - no role change endpoint on this process
                     reason:  role changes handled by identity service, separate tier
R Repudiation     -> threat: charge with no actor record
                     control: authz.decision + payment.charge audit events
                     where:   audit/emit.go:12
```

**Why this matters:** The first grid records that a review happened but cannot be retested, and the 'actions to follow' line is where these models die. The second gives every surviving row a control and a file, and the one empty row carries a reason instead of a dash, so the next reviewer knows the omission was deliberate.

## When It Is NOT This Issue

- **Every element marked with every letter.** A grid where all six categories apply everywhere was filled in without reading the element; unmarked categories need reasons, not default threats.
- **Threat requiring an actor outside the diagram.** Insider database access or physical access belongs to a different model; record the handoff instead of stretching this one.
- **Control listed as 'validation' with no location.** That is an intention; it becomes a control when a file and function enforce it.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `threat-modeling-stride-analysis` based solely on surface keywords (`STRIDE`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `threat-modeling-stride-analysis` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: threat-modeling-stride-analysis
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-20`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`threat-modeling`](../threat-modeling/SKILL.md) - Application Security (core)
- [`threat-modeling-attack-tree-and-misuse-cases`](../threat-modeling-attack-tree-and-misuse-cases/SKILL.md) - Application Security (leaf)
- [`secure-code-review`](../secure-code-review/SKILL.md) - Application Security (flagship)
- [`secure-sdlc-and-security-requirements`](../secure-sdlc-and-security-requirements/SKILL.md) - Application Security (core)
- [`secure-design-patterns`](../secure-design-patterns/SKILL.md) - Application Security (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `threat-modeling-stride-analysis` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/gh_advisories (2), CYBER_CPT/expku (2), CYBER_CPT/osv (1), CYBER_CPT/go_exploitdb (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
