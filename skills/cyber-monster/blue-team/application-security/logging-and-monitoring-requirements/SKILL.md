---
name: logging-and-monitoring-requirements
description: "Defines what an application must log for security: authentication events, authorization decisions, sensitive operations and log integrity. Use when specifying application telemetry."
family: application-security
tier: leaf
triggers: ["application logging requirements", "security logging design", "log integrity"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [secure-code-review, threat-modeling, secure-sdlc-and-security-requirements, secure-design-patterns]
---

# Logging and Monitoring Requirements - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Application Security`](../README.md) | Tier: **leaf** | Paired Counterpart: [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md)

## Mechanism and Preconditions

Logging requirements are the contract between the application and whoever investigates an incident later: which security events must be recorded, which fields they must carry, how long they survive, and how they are protected from the application that writes them. The requirement is met only when a collected event answers 'who did what to which object, from where, and was it allowed' without joining to a database the attacker may have modified. OWASP ASVS 5.0.0 chapter V16 (Security Logging and Error Handling) and OWASP Top 10:2025 A09 (Security Logging and Alerting Failures) are the current framing for that contract.

- **CWE-778 (Insufficient Logging):** the absence of a decision record, not a malformed one; you cannot reconstruct authorisation outcomes after the fact.
- Requirements must name the field, not the intention: `actor.id`, `actor.tenant`, `resource.id`, `decision`, `source.ip`, `trace_id`, `event.outcome`.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the system must satisfy an audit regime **THEN** map each requirement to an ASVS V16 clause or a CIS Safeguard id before writing pipeline code, so the evidence has a name.
2. **IF** the ask is detection content rather than requirements **THEN** switch to the detection-and-monitoring family; this skill defines the contract, not the alert.
3. **IF** the concern is log tampering during an incident **THEN** pair this with the incident-response evidence-handling playbook so preservation order is decided in advance.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate the security decisions the system makes.** Sign-in, step-up, authorisation deny, privilege change, secret access, data export, admin action, and policy reload. Each needs its own event name, because a generic 'request' log cannot distinguish them.
2. **Specify the field set per event.** Actor identity and tenant, resource identity and owner, decision and reason code, source address and user agent, correlation id, and the policy version that produced the decision. Missing fields are the real cause of investigations that stall.
3. **Choose the branch by who must read the log.** Compliance evidence needs immutability and retention beyond the app's reach; engineering debugging needs volume and low latency; security detection needs the fields above plus a stable schema. One pipeline rarely serves all three.
4. **Define the baseline-vs-probe differential.** Baseline: a successful authorised request logs one event with `decision=allow`. Probe: the same request denied, and one with the app's logger level raised. The probe must still produce the security event — logging that disappears when verbosity is reduced is not a control.
5. **State the stop condition and the proof.** Stop when every enumerated decision produces an event with the full field set, verified by a synthetic transaction in production; proof is the query result for that synthetic actor, not the logging library configuration.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Authorisation deny with no `decision` field | Proves the event records a request but not a verdict, so denials cannot be counted on any stack that logs only at the framework's access-log layer. |
| Security event suppressed by log level | Proves the control depends on deployment configuration; raising log level for volume control is the usual cause of a blind spot during an incident. |
| Application credentials able to delete or rewrite its own log stream | Proves the log is not evidence; ASVS V16 expects write-only access from the producer. |
| Event without tenant or owner identity | Proves cross-tenant investigations will be impossible; multi-tenant SaaS finds this only when a customer asks for their audit trail. |

## Worked Contrast

**Requirement met on paper only (access log, no decision record):**

```python
logger.info("request", extra={"path": request.path, "user": request.user})

# access log line emitted by the server:
# 10.0.0.5 - - [14/Nov/2026] "GET /api/invoices/77 HTTP/1.1" 403 -
```

**Decision event with the field set an investigator needs:**

```python
audit.emit(
    event="authz.decision",
    outcome="deny",
    reason="tenant_mismatch",
    actor={"id": user.id, "tenant": user.tenant_id, "roles": user.roles},
    resource={"type": "invoice", "id": inv_id, "tenant": inv.tenant_id},
    source={"ip": request.client.host, "ua": request.headers.get("user-agent")},
    policy={"engine": "opa", "version": POLICY_VERSION},
    trace_id=trace_id,
    emit_level="always",       # not subject to LOG_LEVEL
)
```

**Why this matters:** The access log proves a 403 happened but not who was refused, for which tenant, or under which policy. The second form names the decision, the reason, the tenant on both sides, and bypasses the verbosity setting, which is what makes the event usable during an investigation and countable in a detection.

## When It Is NOT This Issue

- **Access log accepted as the security event.** Some gateways do emit actor and verdict fields; check the field list before requiring a duplicate event from the app.
- **PII in logs flagged as a finding when it is a classified, retention-bounded field.** A masked account id in an audit event is legitimate; an unmasked document body is not.
- **Missing events from a system that never makes the decision.** A static asset CDN does not need authorisation events; scope the requirement to the components that decide.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `logging-and-monitoring-requirements` based solely on surface keywords (`auth event`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `logging-and-monitoring-requirements` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: logging-and-monitoring-requirements
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-778`): [Exact lines/component, broken invariant, reachability, and concrete impact]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `logging-and-monitoring-requirements` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/osv (2), CYBER_CPT/go_exploitdb (2), cyber-security/CyberSec-Dataset (1), CYBER_CPT/gh_advisories (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
