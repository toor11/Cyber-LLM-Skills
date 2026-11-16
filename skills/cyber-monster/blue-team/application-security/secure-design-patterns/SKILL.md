---
name: secure-design-patterns
description: "Applies secure design patterns: authentication and authorization architecture, input handling boundaries, secret management and fail-safe defaults. Use when designing systems rather than reviewing them."
family: application-security
tier: core
triggers: ["secure design", "design pattern security", "fail safe default"]
cwe: [CWE-657]
owasp: []
attack: []
capec: [CAPEC-116]
related: [secure-code-review, threat-modeling, secure-sdlc-and-security-requirements, secrets-management-and-key-custody]
---

# Secure Design Patterns - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Application Security`](../README.md) | Tier: **core** | Paired Counterpart: [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md)

## Mechanism and Preconditions

Secure design is the choice of where a control lives, made before the code exists: which component is allowed to decide, what happens when that component is unavailable, and how the decision is recorded. Reviewing a design means asking what the system does when the control is skipped — the default-deny path, the failure mode, and the blast radius of a single compromised credential. A design is defensible when each of those three answers is written down and matches the deployed configuration.

- **CWE-657 (Violation of Secure Design Principles):** the defect is structural — the control sits where it cannot see the data, or fails open when the dependency is missing.
- Fail-safe means the deny branch is the one that runs on timeout, parse error, and missing config; a control that fails closed only on the happy path is not a control.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the design is not yet drawn **THEN** produce the boundary and data-class inventory with `threat-modeling` first; design patterns are only meaningful against named boundaries.
2. **IF** the design is already built and you are reviewing as-built configuration **THEN** switch to `security-architecture-review` in the program family.
3. **IF** the question is specifically which cloud identity or network construct to use **THEN** open `hardening-cloud-and-containers-identity-and-policy-hardening` or `zero-trust-and-mtls-service-mesh-hardening` rather than inventing a pattern here.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the decision point for every protected action.** Name the single component that decides authorisation for each resource type. Two decision points means the weaker one wins under load or code drift.
2. **Trace the data the decision needs.** If the deciding component cannot see tenant, ownership, or classification without a second call, the design will drift into trusting a caller-supplied value.
3. **Choose the branch on the failure mode.** For each control, decide fail-closed (deny on timeout), fail-open-with-alarm (permit but page), or degrade (serve cached, read-only). Write the choice into the design; an unstated failure mode is always fail-open in practice.
4. **Define the baseline-vs-probe differential.** Baseline: a normal authorised request. Probe: the same request with the control's dependency unavailable (stopped sidecar, expired token, empty policy bundle). The design holds only if the probe is denied or degraded as documented.
5. **State the stop condition and what counts as proof.** Stop when each control has a located decision point, a documented failure mode, and a probe that confirms it; proof is the probe result plus the config line that sets the mode.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Authorisation decided in the browser or in a shared layout | Proves the control is advisory on a SPA or Next.js stack; any direct API call bypasses it, and CVE-2026-64642 (Next.js middleware bypass via Turbopack single-locale) is the framework-level version of the same mistake. |
| Single credential reaching several trust zones | Proves missing capability separation; one compromise spans the zones, which is the pattern behind most lateral movement after an app compromise. |
| Policy bundle or token cache with no failure mode | Proves fail-open by omission on any stack using OPA, Envoy ext_authz, or a JWT cache. |
| Tenant identifier accepted from the request body | Proves the decision point cannot derive scope itself, so it trusts the caller — the structural cause of the object-level findings in OWASP Top 10:2025 A01. |

## Worked Contrast

**Design that fails open (authorisation dependency has no deny path):**

```python
def can_read(user, doc_id):
    try:
        return policy.check(user, "read", doc_id)   # remote call
    except Exception:
        return True                                  # dependency down -> allow
```

**Design that fails closed with an explicit degraded mode:**

```python
class Decision(Enum):
    ALLOW = "allow"; DENY = "deny"; DEGRADED = "degraded"

def can_read(user, doc_id, *, deadline=0.05):
    try:
        return ALLOW if policy.check(user, "read", doc_id, timeout=deadline) else DENY
    except (TimeoutError, ConnectionError):
        metrics.increment("authz.degraded")
        return DEGRADED          # caller must serve 503, never the document
```

**Why this matters:** The first version converts an outage into a full authorisation bypass, which is the exact failure a reviewer should catch on the diagram. The second makes the degraded state a value the caller must handle, so the deny branch is the only one that can run when the policy service is unreachable.

## When It Is NOT This Issue

- **Control is enforced by the platform data plane.** Row-level security, mesh authorisation policy, or a gateway's JWT validation can be the decision point; verify it in config before asking the application to duplicate it.
- **Fail-open is a documented, compensated decision.** A read-only cache serving stale content during an outage is a business decision with an alarm and a compensating control, not a design defect.
- **Single credential with a scoped, short-lived token.** A workload identity that is minted per request with a narrow audience is capability separation even though it is one credential type.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `secure-design-patterns` based solely on surface keywords (`centralized authz`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `secure-design-patterns` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: secure-design-patterns
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-657`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`secure-code-review`](../secure-code-review/SKILL.md) - Application Security (flagship)
- [`threat-modeling`](../threat-modeling/SKILL.md) - Application Security (core)
- [`secure-sdlc-and-security-requirements`](../secure-sdlc-and-security-requirements/SKILL.md) - Application Security (core)
- [`secrets-management-and-key-custody`](../secrets-management-and-key-custody/SKILL.md) - Application Security (core)
- [`security-testing-in-ci-cd`](../security-testing-in-ci-cd/SKILL.md) - Application Security (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `secure-design-patterns` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-657`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 22 |
| Distinct dataset sources | 5 |
| Top sources | OffsecCyber (16), SecEval/cwe (2), CYBER_CPT/go_exploitdb (2), SecEval/owasp_mastg (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 3 cases |
| Grounding | multi-dataset corpus-grounded |
