---
name: business-logic-flaws-workflow-and-state
description: Workflow and state machine bypass. Covers skipping or reordering steps, replaying completed steps, and forcing states that the UI never exposes. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["workflow bypass", "state machine abuse", "step skip", "process bypass"]
cwe: [CWE-840]
owasp: [A04:2021]
attack: []
capec: [CAPEC-74]
related: [business-logic-flaws, business-logic-flaws-payment-and-pricing, business-logic-flaws-quota-and-rate, sql-injection]
parent: business-logic-flaws
corpus_sparse: true
---

# Business Logic Flaws Workflow and State - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

This variant targets multi-step processes whose safety depends on an ordering the server never re-checks: checkout before payment, email verification before a privilege grant, KYC before withdrawal, approval before publish. Each step is its own endpoint, and the flaw is that a later endpoint executes without confirming the server-side record is in the required prior state, or it lets a completed step be replayed so its effect compounds. The attacker calls transitions out of order, skips a gating step, or replays a one-time step, driving the record into a state the UI never exposes. The gain is a privilege or payout reached without its precondition; confirmation is a persisted record sitting in a state its own transition rules forbid.

- **Precondition chain:** A process relies on step ordering, each step is an independently callable endpoint, the server authorises a transition without checking the record is in the required prior state, and the out-of-order or replayed call persists a forbidden state.
- **Readable differential:** The process driven in the intended order versus the same endpoints called with a step skipped, reordered, or replayed; a finding exists when the out-of-order run reaches a privileged state and the in-order run cannot, and it closes once each transition is guarded by the current server-side state.
- **Empirical grounding:** CWE-840 Business Logic Errors under OWASP Top 10:2025 A06:2025 Insecure Design, with CWE-841 Improper Enforcement of Behavioral Workflow as the ordering-specific taxonomy. This leaf is corpus-sparse and SOURCES.md lists no state-machine-specific advisory, so the grounding stays at the CWE-840 / CWE-841 taxonomy level rather than naming a CVE.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match workflow or state-machine logic **THEN** start at parent class [`business-logic-flaws`](../business-logic-flaws/SKILL.md) first
2. **IF** a later endpoint executes without checking the record is in its required prior state **THEN** treat the missing transition guard as the sink and verify server-side state
3. **IF** a forced state or step id really reaches a record owned by another principal **THEN** reclassify as object access and read [`authorization-and-idor`](../authorization-and-idor/SKILL.md)
4. **IF** a one-time step can be replayed concurrently so its effect compounds **THEN** route to [`race-conditions-and-concurrency`](../race-conditions-and-concurrency/SKILL.md)
5. **IF** the skippable gate is email or identity verification in account recovery **THEN** read [`password-reset-and-account-recovery`](../password-reset-and-account-recovery/SKILL.md) for that flow's state rules
6. **IF** a status or step token is submitted by the client rather than derived from the record **THEN** focus on server-authoritative state: the client must not name its own state
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** every transition is guarded by the current server-side state and no step is replayable **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Forcing a state reaches another principal's record via its id | [`authorization-and-idor`](../authorization-and-idor/SKILL.md) | Invariant is per-object ownership, not transition ordering |
| A one-time step replayed concurrently compounds its effect | [`race-conditions-and-concurrency`](../race-conditions-and-concurrency/SKILL.md) | Invariant is single execution of a step, a concurrency guard |
| The skipped gate is identity verification during recovery | [`password-reset-and-account-recovery`](../password-reset-and-account-recovery/SKILL.md) | Invariant is the recovery flow's own ordering rules |
| Need parent class methodology | [`business-logic-flaws`](../business-logic-flaws/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Reconstruct the state machine from the endpoints, not the UI.** Enumerate each step as a transition with a from-state and a to-state, and mark which step is the gate (payment, verification, approval) that later steps assume has completed.
2. **Find where each transition reads the current state.** A safe transition loads the record, checks it is in the required from-state, then advances it. A transition that advances without that check, or that trusts a client-supplied status, is the candidate.
3. **Classify the break.** Skip (call a later transition first), reorder (swap two transitions), replay (repeat a one-time step), or force (submit a target status directly). Pick the class the endpoint shape allows.
4. **Record the intended-order baseline.** Drive the full process in order and capture the persisted status at each step, so you know the legitimate terminal state and the gate it required.
5. **Issue the out-of-order or replayed call and read the persisted state.** Call the gated transition without its precondition, or replay a completed step, then fetch the record server-side to see if it advanced. A 200 without a state change is not the flaw.
6. **Stop condition.** Stop when the manipulation either (a) persists a state whose transition rules forbid it from the current from-state and the record cannot reach it legitimately, (b) is rejected because every transition re-checks state, or (c) would require advancing another real user's case or releasing a real payout. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a persisted record in a forbidden state, for example withdrawal-approved with KYC still pending, tied to the specific transition endpoint that skipped its from-state check. A transient UI step indicator is not proof.
8. **Close with the structural fix and verify.** Guard every transition with an explicit from-state check, derive status only from the server record, make one-time steps idempotent, then replay the skip, reorder, and replay probes to confirm each is refused.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A gated endpoint advancing a record without checking its current status | Proves the transition lacks a from-state guard on the workflow engine |
| A status or step field accepted from the client on a write | Proves the state machine trusts caller-named state over the server record |
| A completed one-time step repeatable with a compounding effect | Proves the transition is not idempotent, allowing replay |
| A terminal state reachable without its documented prerequisite step | Proves the gate (payment, KYC, approval) is not enforced server-side |
| A step id or token selecting which transition runs taken from the request | Proves ordering is client-driven rather than server-derived |
| Two orderings producing different persisted outcomes for the same inputs | Proves the process is order-sensitive without enforcing the order |
| A draft or hidden state the UI never shows but the API will set | Proves out-of-band states are reachable through direct transition calls |

## Worked Contrast

**Vulnerable pattern:**

```python
def approve_withdrawal(db, case_id):
    # Advances to approved without checking the KYC gate completed
    case = db.get_case(case_id)
    case.status = 'approved'
    db.save(case)
    release_funds(case)
    return {'status': case.status}
```

**Hardened pattern:**

```python
ALLOWED_FROM = {'kyc_passed'}

def approve_withdrawal(db, case_id):
    # Guard the transition on the current server-side state
    case = db.get_case(case_id)
    if case.status not in ALLOWED_FROM:
        raise ValueError('withdrawal not eligible from state ' + case.status)
    case.status = 'approved'
    db.save(case)
    release_funds(case)
    return {'status': case.status}
```

**Why this matters:** The defective transition forces the approved state regardless of where the case actually is, so a caller skips the KYC gate; the fixed transition checks the record is in the required prior state before advancing, so approval is reachable only after its precondition.

## When It Is NOT This Issue

- **Every transition re-checks state:** if the gated endpoint loads the record and rejects a wrong from-state, skipping and reordering both fail.
- **Idempotent one-time step:** a step that collapses replays to a single effect cannot be compounded.
- **Client indicator only:** a step counter shown in the UI that the server ignores is cosmetic; the persisted state is what matters.
- **Self-only draft record:** reaching an odd state in your own unsubmitted draft, with no privilege or payout, is not a finding.
- **Intended optional step:** a step the business designs as skippable (an optional profile field) is expected, not a workflow bypass.
- **Reached state still gated downstream:** if a forced status is ignored by the next authoritative check (payout still verifies KYC itself), impact is zero.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `business-logic-flaws-workflow-and-state` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `business-logic-flaws-workflow-and-state` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: business-logic-flaws-workflow-and-state
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-840 | Mapping: A04:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`business-logic-flaws`](../business-logic-flaws/SKILL.md) - Web and Application (core)
- [`business-logic-flaws-payment-and-pricing`](../business-logic-flaws-payment-and-pricing/SKILL.md) - Web and Application (leaf)
- [`business-logic-flaws-quota-and-rate`](../business-logic-flaws-quota-and-rate/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `business-logic-flaws-workflow-and-state` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-840`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 2 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/gh_advisories (1), CYBER_CPT/osv (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 2 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
