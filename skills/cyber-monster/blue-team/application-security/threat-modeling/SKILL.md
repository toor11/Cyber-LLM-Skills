---
name: threat-modeling
description: "Produces threat models: system decomposition, trust boundaries, STRIDE or attack-tree analysis and prioritized mitigations. Use at design time or when assessing a new system."
family: application-security
tier: core
triggers: ["threat modeling", "stride", "attack tree", "design review threat", "model threats", "threat model a service"]
cwe: [CWE-20]
owasp: []
attack: []
capec: [CAPEC-116]
related: [threat-modeling-stride-analysis, threat-modeling-attack-tree-and-misuse-cases, secure-code-review, secure-sdlc-and-security-requirements]
---

# Threat Modeling - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Application Security`](../README.md) | Tier: **core** | Paired Counterpart: [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md)

## Mechanism and Preconditions

Threat modelling produces a diagram of what crosses which boundary, a list of the ways each crossing can be abused, and a decision about which of those you are choosing to accept. The artefact that makes it useful is the pairing of every element with the control that would have to fail, so the output can be re-tested when the design changes. Scope is a named system, its data classes, and the actors you can enumerate from real authentication paths.

- **CWE-20 framing:** most modelled abuse cases reduce to a boundary that accepts data it should have rejected, or a caller that is trusted beyond its actual authentication.
- A model without a named owner, a version, and the config it describes cannot be re-validated and is documentation, not a threat model.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the request is about eliciting abuse cases rather than enumerating categories **THEN** open the attack-tree sibling, which starts from adversary goals and decomposes them.
2. **IF** the team wants per-element STRIDE coverage and a worksheet **THEN** open the STRIDE sibling, which carries the element-by-category grid.
3. **IF** the design is already built and you are asked whether it is safe **THEN** redirect to `secure-design-patterns` or `security-architecture-review`; a model of shipped code without the as-built config is fiction.
4. **IF** the target narrows to `threat-modeling-stride-analysis` **THEN** open [`threat-modeling-stride-analysis`](../threat-modeling-stride-analysis/SKILL.md) for the variant-specific evidence set, because the parent checks here stay too coarse for that profile.
5. **IF** the target narrows to `threat-modeling-attack-tree-and-misuse-cases` **THEN** open [`threat-modeling-attack-tree-and-misuse-cases`](../threat-modeling-attack-tree-and-misuse-cases/SKILL.md) for the variant-specific evidence set, because the parent checks here stay too coarse for that profile.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `threat-modeling-stride-analysis` | [`threat-modeling-stride-analysis`](../threat-modeling-stride-analysis/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `threat-modeling-attack-tree-and-misuse-cases` | [`threat-modeling-attack-tree-and-misuse-cases`](../threat-modeling-attack-tree-and-misuse-cases/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Fix scope and data classes before drawing.** Name the system, the trust boundaries (browser to edge, edge to service, service to data store, service to third party), and the data classes that cross each one. Stop expanding scope when a new element adds no boundary.
2. **Confirm each boundary's control against the running configuration.** For every crossing, name the authenticator, the authorisation decision point, and the encoding or validation that runs. A control you cannot point at in config is an assumption, and assumptions go in the risk list.
3. **Choose the branch on what the boundary protects.** Confidentiality crossings get an access-control and data-minimisation branch; integrity crossings get validation, signing, and replay branches; availability crossings get quota and dependency-isolation branches.
4. **Define the baseline-vs-probe differential per threat.** Baseline is a legitimate flow through the boundary; the probe is the same flow with the attacker's substitution (another tenant's id, a replayed token, a truncated body). The model is credible when you can say which observable would differ.
5. **State the stop condition and the proof.** Stop when every boundary crossing has either a named control with an owner or an accepted-risk entry with a review date; proof is the diagram plus the control-to-element mapping, not the list of threats.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Boundary crossing with no authentication on the callee | Proves the caller is implicitly trusted on that hop, which is the standard flat-network finding in a service mesh or internal API. |
| Data class crossing a boundary it is not classified for | Proves a data-flow violation: PII or token material moving into a logging, analytics, or third-party element that has no handling requirement. |
| Control named in the model but absent from config | Proves the model drifted from the deployment; the diff between diagram and config is the finding list for the next review. |
| Trust boundary drawn around a shared runtime | Proves the boundary is nominal — two services in one pod or one database share failure and credential scope, so the control cannot be enforced where it is drawn. |

## Worked Contrast

**Weak model entry (boundary asserted, control never located):**

```text
Boundary: API -> Payments
Threat: attacker tampers with amount
Control: validation
Owner: TBD
Status: mitigated
```

**Defensible model entry (control located in config, probe defined, owner named):**

```text
Boundary: checkout-api -> payments-svc (mTLS, SPIFFE checkout/ns)
Data: order_id, amount_minor, currency, idempotency_key
Threat: caller rewrites amount_minor after pricing
Control: payments-svc recomputes total from order_id (server-side price table)
  evidence: payments/handlers/charge.py:88 price = price_table[order_id]
  not relied on: checkout-api validation (untrusted hop)
Probe: POST charge with amount_minor=1 for an order priced 4999
Expected: 422 amount_mismatch, no charge row, audit event payment.reject
Owner: payments-oncall | Review: 2027-02-01
```

**Why this matters:** The first entry claims a control that no code enforces and cannot be retested; the second names the recomputation, the file that performs it, the hop it deliberately does not trust, and the observable that would change if the control regressed.

## When It Is NOT This Issue

- **Model describes a prototype, not a deployment.** A diagram of the intended architecture is a design input; do not file its gaps as vulnerabilities until the config exists.
- **Boundary is enforced by the platform, not the app.** Managed identity, private endpoints, and network policy can carry the control; cite the platform control before assuming the app must re-implement it.
- **Threat requires an actor outside the model's scope.** Physical access, insider with production database credentials, or a compromised build system belongs to a different model with its own controls.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `threat-modeling` based solely on surface keywords (`data flow diagram`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `threat-modeling` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: threat-modeling
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-20`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`threat-modeling-stride-analysis`](../threat-modeling-stride-analysis/SKILL.md) - Application Security (leaf)
- [`threat-modeling-attack-tree-and-misuse-cases`](../threat-modeling-attack-tree-and-misuse-cases/SKILL.md) - Application Security (leaf)
- [`secure-code-review`](../secure-code-review/SKILL.md) - Application Security (flagship)
- [`secure-sdlc-and-security-requirements`](../secure-sdlc-and-security-requirements/SKILL.md) - Application Security (core)
- [`secure-design-patterns`](../secure-design-patterns/SKILL.md) - Application Security (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `threat-modeling` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 33 |
| Distinct dataset sources | 11 |
| Top sources | OffsecCyber (21), SecEval/owasp_wstg (3), SecEval/mit6.858 (1), bug-bounty-pentest-en (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
