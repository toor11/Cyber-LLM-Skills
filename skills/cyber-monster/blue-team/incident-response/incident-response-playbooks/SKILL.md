---
name: incident-response-playbooks
description: "Builds and runs incident response playbooks: severity definition, roles, phases from detection through closure, and playbook maintenance. Use when responding to an incident or authoring response procedures."
family: incident-response
tier: flagship
triggers: ["incident response", "ir playbook", "incident handling", "response procedure"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [ir-triage-and-timeline, containment-and-eradication, ransomware-response, business-email-compromise-response]
---

# Incident Response Playbooks - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Incident Response`](../README.md) | Tier: **flagship** | Paired Counterpart: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md)

## Mechanism and Preconditions

A playbook is not a description of the phases; it is a set of pre-made decisions that removes negotiation from the worst hour of the incident. NIST SP 800-61r3, finalised in April 2025 as a CSF 2.0 community profile, deliberately stopped prescribing phases, because the details of response vary too much across technologies and organisations to hold in one static document. What it does require is what a playbook must supply: named definitions of event, incident and investigation; roles, responsibilities and authorities — explicitly including which roles may confiscate, disconnect or shut down technology assets; guidelines for prioritisation and severity; and performance measures. CISA's Federal Government Cybersecurity Incident and Vulnerability Response Playbooks remain a usable procedural reference outside federal service, provided the agency-specific coordination steps are replaced with ones that have an independent legal or contractual basis. The distinguishing property of a playbook that works is that it fails visibly: each step has an entry condition, an owner, an artefact it produces, and a condition that marks it complete. A playbook written as prose ("responders should assess the scope") produces no artefact and cannot be audited, so it degrades into whatever the most senior person present believes, and the post-incident review cannot distinguish a decision from an accident. Precondition for all of it: the severity taxonomy and the authority matrix must exist before the incident, because the moment a decision is needed is the moment renegotiating it costs the most.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** an incident has no assigned severity under an existing taxonomy **THEN** assign one from the published criteria before any containment action, because severity determines who is authorised to act and who must be told.
2. **IF** the playbook step requires an authority the responder does not hold (isolating a domain controller, taking a service offline) **THEN** escalate to the role named in the authority matrix rather than acting and informing afterwards; **IF** no such role is named **THEN** that absence is the finding, and it belongs in the review.
3. **IF** the incident is a known pattern with a dedicated sub-skill **THEN** use that playbook's procedure and keep this one for severity, roles, escalation and closure; a generic procedure applied to a specific technique produces steps that do not fit.
4. **IF** a regulatory, contractual or insurance clock applies **THEN** start it explicitly with its trigger recorded, and treat the playbook as responsible for that recording.
5. **IF** a playbook step has produced no artefact at its completion condition **THEN** treat the step as not done, regardless of what the responder reports.
6. **IF** telemetry source covering `severity` / `roles` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).
8. **IF** required preconditions for `incident-response-playbooks` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need the timeline before deciding | [`ir-triage-and-timeline`](../ir-triage-and-timeline/SKILL.md) | Ordering and evidence before containment choices |
| Need containment method detail | [`containment-and-eradication`](../containment-and-eradication/SKILL.md) | Primitives, collateral and re-entry validation |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Evidence classes for severity, authority and closure attestation |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Case-record and timeline tooling |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the playbook you are running exists and is current.** Check its version, its last exercise date, and whether the roles it names still exist in the organisation. A playbook with a leaver in the approver slot is a playbook that will be improvised under pressure.
2. **Choose the branch by severity and by pattern.** Severity selects the authority level and the notification set; the pattern selects the technique-specific procedure and its evidence sources. Record both, because a review that cannot see which severity was assigned cannot judge whether the response was proportionate.
3. **Define the baseline that makes progress measurable.** For each phase, state what the normal state is before the incident and what observable change marks the phase as entered and as complete. Without this, phase transitions are declared rather than established, and the timeline records opinions.
4. **State the stop condition.** A phase stops at its completion condition with its artefact present. The incident stops when containment is attested at the enforcing layer, eradication is validated over a monitored window, notification obligations are filed with receipts, and the lessons-learned items have owners and dates. Any phase declared complete without its artefact reopens.
5. **Prove the response, not the compliance.** The proof is the artefact set: the timeline with its sources, the containment attestation from the enforcing layer, the notification receipt with a timestamp, and the review with named owners for each action. A playbook that was followed is evidenced by what it produced; a checklist of completed steps without artefacts evidences only that someone clicked.

## Concrete Patterns

| Indicator / Artifact | Evidence class | What it proves |
|---|---|---|
| Severity assigned with the criterion that was met, and the timestamp | Case record | The response level was chosen against published criteria rather than by seniority in the room |
| Authority record naming who approved each disruptive action and when | Approval log | The action was within someone's remit, which is the question asked in every review and every legal challenge |
| Phase-completion artefact per phase, such as a containment attestation or a filing receipt | Case artefacts | The phase actually completed, as opposed to being declared complete in a status update |
| Notification clock entry with its trigger event and evidence | Obligation register | When the duty started and what it was based on, which is the only defence to a late-filing allegation |
| Playbook version and last exercise date at the time of use | Document control record | Whether the procedure was current; a stale playbook explains gaps that would otherwise read as incompetence |
| Lessons-learned item with an owner and a due date, and a later closure reference | Remediation tracker | That the review produced a change, not just a document |

## Worked Contrast

**Brittle / Single-Indicator or Missing-Telemetry Practice (`severity`):**

```text
# ANTI-PATTERN: severity decided by whoever is loudest at 03:00.
# Containment actions taken without an authority record.
# Status updates say "scope assessed" because someone read a dashboard.
# The review cannot reconstruct who decided what, so it recommends
# "improve communication" and the same gap recurs next quarter.
```

**Behavior-Anchored Detection & Guarded Triage (`severity` — CWE-778):**

```yaml
title: Verified Behavior Check - incident-response-playbooks
severity_criteria:
  sev1: { criteria: "confirmed destructive action or safety impact", notify: [ic, exec, legal, regulator_if_applicable], authority: incident_commander }
  sev2: { criteria: "confirmed intrusion, no destructive action", notify: [ic, security_lead], authority: security_lead }
  sev3: { criteria: "suspected intrusion, scope unknown", notify: [on_call], authority: on_call_analyst }
authority_matrix:
  isolate_endpoint: security_lead
  isolate_domain_controller: incident_commander_with_exec_notification
  revoke_privileged_identity: incident_commander
  notify_regulator: legal_counsel
phase_artefacts:
  triage:      "timeline with named sources"
  containment: "enforcing-layer attestation plus failed egress attempt"
  eradication: "monitored window with detection version recorded"
  closure:     "review with owned actions and dates"
proof_rule: |
  a phase counts as complete only when its artefact exists;
  a status update is not an artefact
```

**Why this matters:** Pairs `severity` with `roles` context, filters documented admin baselines, and enforces telemetry-presence verification.

## When It Is NOT This Issue

- **A tabletop or notification drill:** exercises produce approvals, notifications and timestamps indistinguishable from a real event in the record. Confirm against the exercise schedule and label the artefacts as exercise.
- **A detection-only event with no confirmed impact:** an alert that fired and was investigated is an event, not an incident, and running the full playbook on it inflates severity history and trains responders to skim. Use the triage path, not the incident path.
- **A vendor or supplier incident that does not affect your systems:** your playbook governs your estate; the supplier's obligations are theirs. Confirm whether any of your data or dependencies are actually implicated.
- **A planned change that resembles incident response:** disaster-recovery tests, failovers and mass rotations look like containment. Check the change calendar and the test window boundary.
- **A recurring alert with a documented benign cause:** running the playbook each time it fires consumes the capacity needed for the real event. The correct action is an exclusion with an owner, not a response.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `severity` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Playbook current:** version, last exercise date and named role holders were confirmed as valid at the time of use, and any leaver in an approver slot is recorded as a gap.
- [ ] **Severity criterion recorded:** the assigned severity names the published criterion it met, with a timestamp, rather than reflecting seniority or convenience.
- [ ] **Authority named per disruptive action:** every isolation, revocation or shutdown has an approver and a time, drawn from a matrix that existed before the incident.
- [ ] **Phase artefacts present:** each phase claimed complete has its artefact, and phases without one are reopened rather than carried forward.
- [ ] **Closure owned:** every review action has an owner and a date, and the remediation tracker is the closure criterion rather than the review document itself.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: incident-response-playbooks
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`ir-triage-and-timeline`](../ir-triage-and-timeline/SKILL.md) - Incident Response (core)
- [`containment-and-eradication`](../containment-and-eradication/SKILL.md) - Incident Response (core)
- [`ransomware-response`](../ransomware-response/SKILL.md) - Incident Response (flagship)
- [`business-email-compromise-response`](../business-email-compromise-response/SKILL.md) - Incident Response (core)
- [`web-application-incident-response`](../web-application-incident-response/SKILL.md) - Incident Response (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `incident-response-playbooks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 43 |
| Distinct dataset sources | 12 |
| Top sources | Forensic_Toolkit_Dataset (12), CYBER_CPT/L5/ctf_search (11), SecEval/attck (5), cyber-security/CyberSec-Dataset (5) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 12 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
