---
name: security-architecture-review
description: "Reviews system architecture for security: trust boundaries, data flows, control placement and failure modes. Use when evaluating a design before or after build."
family: purple-team-and-program
tier: core
triggers: ["security architecture review", "design assessment", "architecture security"]
cwe: [CWE-693]
owasp: []
attack: []
capec: [CAPEC-116]
related: [purple-teaming-and-adversary-emulation, remediation-tracking-and-verification, security-program-and-control-frameworks, control-testing-and-audit-evidence]
---

# Security Architecture Review - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Purple Team and Program`](../README.md) | Tier: **core** | Paired Counterpart: [`red-team-operations-and-scoping`](../../../red-team/osint-and-red-operations/red-team-operations-and-scoping/SKILL.md)

## Mechanism and Preconditions

An architecture review asks whether the controls are placed where they can see the data, and what happens when each one fails. It is a design-time review even when the system already runs, because the subject is the intended structure: trust boundaries, data flows, and the failure mode of every control on the path. The output is a set of findings about placement and failure, not a configuration audit - though each finding should name the config evidence that would confirm it.

- **CWE-693 framing:** the review is about protection mechanism placement and failure behaviour, which is why 'a control exists' is not the same as 'a control is positioned to work'.
- Every control has a failure mode; if the design does not state it, the implementation will choose fail-open by default.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the diagram does not exist **THEN** produce the boundary and data-class inventory with `threat-modeling` first.
2. **IF** the review concerns specific patterns (fail-safe, capability separation) **THEN** open `secure-design-patterns`.
3. **IF** the question is segmentation between zones **THEN** open `network-segmentation-and-architecture-review`.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Reconstruct the as-built data flow.** Not the intended diagram: the flow observed in logs and configuration. Record each hop, the data class crossing it, and the control at that hop.
2. **Test control placement against the data.** For each control, ask what it can see: a WAF cannot inspect what it does not decrypt, a gateway cannot authorise what resolves inside the app, an application check cannot see a second path around it.
3. **Choose the branch on the failure mode.** Fail-closed controls take the availability-impact branch; fail-open controls take the compensating-detection branch; controls with an undefined failure mode take the design-gap branch and are the primary finding.
4. **Define the baseline-vs-probe differential.** Baseline: a normal flow through the control. Probe: the same flow with the control's dependency unavailable or the control bypassed. The design holds only if the probe is denied or explicitly degraded.
5. **State the stop condition and the proof.** Stop when every control has a placement justification and a documented failure mode, and the bypass probe has been run; proof is the probe result plus the config line that sets the mode.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Control placed after a component that can act on the data first | Proves the control is decorative for that path; the earlier component already made the decision. |
| Authorisation enforced only at the edge gateway | Proves any internal caller, or any path that bypasses the gateway, is unauthorised-but-permitted. |
| Control with no documented failure mode | Proves the implementation will default to fail-open under dependency failure. |
| Two paths to the same data store with different controls | Proves the weaker path sets the effective protection, which is the classic as-built finding. |

## Worked Contrast

**Architecture described by components and their intended controls:**

```text
Architecture (as documented)
Browser -> CDN -> WAF -> API gateway (auth) -> service -> database
- WAF blocks injection
- gateway enforces authorisation
- service validates input
- database encrypted at rest
Review outcome: controls present at every layer
```

**As-built flow with placement justification and failure modes:**

```text
As-built flow (verified from logs and config 2026-11-12)
Browser -> CDN -> WAF -> ALB -> api-svc -> rds

hop            data class   control              can it see the data?         failure mode
CDN            public       TLS, cache policy    no payload inspection        fail-open (cache)
WAF            public       managed rules        HTTP only, no TLS inspect    fail-open on rule failure
ALB            identity     none                 n/a                          n/a
api-svc        PII          authz in code +      yes, full payload            fail-open (see probe)
                            gateway check
rds            PII          KMS at rest, RLS     yes                          fail-closed

Findings
A-1  authorisation exists in both gateway and service, but the batch endpoint in api-svc
     resolves objects without the gateway path (direct SQS consumer) -> unauthorised path exists
     evidence: consumer code path order_events/handler.py:44; no gateway in front of SQS
A-2  WAF does not inspect TLS-terminated payloads; injection rules provide no coverage
A-3  authz dependency failure mode undefined; probe with gateway stopped returned 200 -> fails open
probe: stopped gateway sidecar on api-0, request to /v1/invoices returned 200 with data
```

**Why this matters:** The first review confirms every layer has a control, which is true and irrelevant because placement and failure are unexamined. The second records what each control can actually see, runs the dependency-failure probe, and finds the path that bypasses the gateway entirely - which is the finding the diagram could not show.

## When It Is NOT This Issue

- **Control that exists at two layers with the same rule.** Redundancy is not a placement problem; the finding is a layer that cannot see the data.
- **Fail-open on a non-security control.** Caching and compression failing open is a performance decision; only security controls need fail-closed or explicit degradation.
- **Bypass path that is unreachable from untrusted networks.** An internal-only path is still a finding but lower severity; check the exposure before escalating.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `trust boundary` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `security-architecture-review` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: security-architecture-review
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-693 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`red-team-operations-and-scoping`](../../../red-team/osint-and-red-operations/red-team-operations-and-scoping/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`purple-teaming-and-adversary-emulation`](../purple-teaming-and-adversary-emulation/SKILL.md) - Purple Team and Program (core)
- [`remediation-tracking-and-verification`](../remediation-tracking-and-verification/SKILL.md) - Purple Team and Program (core)
- [`security-program-and-control-frameworks`](../security-program-and-control-frameworks/SKILL.md) - Purple Team and Program (core)
- [`control-testing-and-audit-evidence`](../control-testing-and-audit-evidence/SKILL.md) - Purple Team and Program (core)
- [`risk-assessment-and-treatment`](../risk-assessment-and-treatment/SKILL.md) - Purple Team and Program (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `security-architecture-review` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 18 |
| Distinct dataset sources | 10 |
| Top sources | cyber-security/CyberSec-Dataset (8), CYBER_CPT/github_security_md (2), cyber-security/security-code (1), OffsecCyber (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
