---
name: tabletop-exercise-design
description: "Designs and runs tabletop exercises: scenario construction, inject design, participant roles and after-action improvement. Use when testing incident readiness."
family: incident-response
tier: leaf
triggers: ["tabletop exercise", "ttx design", "incident simulation"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [incident-response-playbooks, ir-triage-and-timeline, containment-and-eradication, ransomware-response]
---

# Tabletop Exercise Design - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Incident Response`](../README.md) | Tier: **leaf** | Paired Counterpart: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md)

## Mechanism and Preconditions

A tabletop exercise is a facilitated discussion of a scripted scenario, conducted against the organisation's current plans rather than against an idealised version of them. Its purpose is not to demonstrate competence but to surface the decision points where the plan is silent, ambiguous or contradicts another plan. That makes design a subtractive discipline: the value of an inject is measured by how sharply it forces a decision that the plan does not already answer, and an inject that simply adds detail to a scenario everyone agrees about produces agreement rather than insight. NIST SP 800-61r3 moved improvement out of a terminal phase and into the CSF 2.0 Identify function as a continuous activity, so a modern exercise should be designed to feed that loop — each exercise tests a specific hypothesis about a specific capability, and each finding lands as an owned action with a verification method rather than as a note in an after-action report. The precondition is facilitation independence: whoever designed the scenario should not be the person whose plan is being tested, or the exercise becomes a confirmation.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the exercise has no written objectives **THEN** **STOP** and write them first; an objective-free tabletop produces a discussion, an agenda and no findings.
2. **IF** the objective is a technical capability — detection, containment speed, evidence preservation **THEN** take the operational branch, which needs a scenario grounded in a real campaign and injects timed against a clock.
3. **IF** the objective is a decision or authority question — who may isolate, who may notify, who may speak publicly **THEN** take the governance branch, where the scenario's job is to put two legitimate obligations in conflict and see which one the plan resolves.
4. **IF** the organisation has never exercised **THEN** run a discussion-based tabletop on a scenario the participants already understand before introducing an unfamiliar threat class; the first exercise tests the process for exercising, not the plan.
5. **IF** senior leadership will attend **THEN** design the injects around their decision points and put the technical detail in an appendix; an executive who is walked through packet captures learns nothing about their own authority.
6. **IF** the scenario requires data the organisation cannot supply — a real network map, a real contract clause **THEN** include the gap as a finding rather than inventing the data, because the inability to produce it is the result.
7. **IF** an after-action report is produced without owners and dates **THEN** treat the exercise as incomplete; findings without owners do not survive the next quarter.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need the scenario, inject and evidence classes | [`QUERIES.md`](QUERIES.md) | Objective-to-inject traceability, participation records, action verification |
| Need facilitation and recording tooling | [`TOOLS.md`](TOOLS.md) | Timers, recording, AAR templates |
| Need the design and conduct sequence | [`PLAYBOOK.md`](PLAYBOOK.md) | Objective setting, conduct, hot wash, action tracking |
| Need real-world case cards | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Exercising a ransomware decision chain | [`ransomware-response`](../ransomware-response/SKILL.md) | Real decision points to script |
| Exercising disclosure and notification | [`legal-and-regulatory-notification`](../legal-and-regulatory-notification/SKILL.md) | The clocks and recipients to test |
| Turning findings into tracked work | [`post-incident-review-and-lessons`](../post-incident-review-and-lessons/SKILL.md) | Action ownership and verification |

## Procedure

1. **Confirm the evidence source for the scenario before writing it.** Establish what the organisation can actually show a facilitator: the incident response plan's current version and owner, the last exercise's after-action report and its open actions, the escalation directory, and the actual contract clauses that impose notice deadlines. A scenario built on an assumed plan tests nothing, because participants will discuss the plan they believe exists.
2. **Choose the branch from the objective.** Operational branch for capability objectives — timing matters, injects arrive on a clock, and the facilitator measures response intervals. Governance branch for decision objectives — timing matters less than the sequence of authority, and injects are designed to create obligation conflict. Participation branch when the objective is cross-functional, which requires role players who disagree legitimately.
3. **Define the objective-to-inject differential.** For each objective, state the decision or action that would demonstrate it and the inject that forces it. An inject that no objective predicts is noise, and an objective with no inject is untested. The ratio between them is the exercise's real coverage.
4. **Bound the exercise and name the stop condition.** State duration, participants, scenario scope and the safety rules — no blame, no real systems touched, no live credentials used, and a facilitator empowered to stop a discussion that has become a recrimination. Stop and redesign when participants cannot engage because the scenario requires knowledge they do not hold, when a live incident begins during the exercise, or when a finding requires immediate real-world escalation rather than an action item.
5. **State what counts as proof.** Proof that an objective was tested is a decision recorded during conduct with the role who made it and the information they had at the time. Proof that a finding is real is a documented gap between the plan and what participants actually did, corroborated by the plan text or the missing artifact. An opinion expressed in the hot wash is not a finding until it names something specific and someone owns it.

## Concrete Patterns

| Indicator / Artifact | Evidence class | What it proves |
|---|---|---|
| Objective-to-inject matrix with one row per objective | design record | Whether each objective is actually forced by an inject, or merely discussed |
| Decision log captured live with time, role and information available | conduct record | What participants decided and on what basis, which is what the action items attach to |
| Plan excerpt that the inject contradicted | plan evidence | The gap is in the plan, not in the participants; the fix is a document change |
| Missing artifact the scenario required (contact list, contract clause, network diagram) | evidence gap | A readiness deficiency independent of anyone's performance |
| Hot-wash themes ranked by frequency across roles | conduct record | Which gaps are systemic rather than one role's misunderstanding |
| Action item with owner, date and verification method | improvement record | Whether the exercise will change anything, or produce a document nobody reopens |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
# WEAK: a scenario with no objective, an agenda with no injects, findings with no owners.
09:00 Welcome
09:15 "A ransomware attack happens. What do you do?"
10:30 Discussion
11:00 Wrap-up
Output: "Participants found the session valuable."
```

**High-Signal Grounded Artifact:**

```yaml
exercise: TTX-2026-04
plan_under_test: IRP v7.2, plus DPA clause 9.3 (72h customer notice)
objectives:
  - id: OBJ-1
    statement: Decide whether to isolate the ERP cluster before or after notifying customers.
    demonstrates: A named authority makes the call and records the reasoning.
    inject: INJ-3
  - id: OBJ-2
    statement: Establish the notification clock from an evidenced awareness time.
    demonstrates: Participants name a timestamp and its source, not a recollection.
    inject: INJ-5
injects:
  - id: INJ-3
    at: T+00:45
    content: ERP encrypting; customer order portal still up; contract requires notice in 72h.
    forces: Authority conflict between operations, legal and account management.
  - id: INJ-5
    at: T+01:20
    content: The only record of first awareness is a chat message with no timestamp.
    forces: Recognition that the clock cannot be evidenced as-is.
safety_rules:
  - No live credentials or real customer data in the room.
  - Facilitator stops any discussion that names an individual as at fault.
outputs_required:
  - decision log with role and information-available column
  - one action per gap, with owner, date, verification method
```

**Why this matters:** the strong form ties every inject to a named objective and a decision it is designed to force, so the conduct record shows whether the plan answered the question or the participants improvised; the weak form produces a discussion, a satisfaction rating and no testable claim about readiness.

## When It Is NOT This Issue

- **A training session or awareness briefing:** teaching people what ransomware is does not test whether the plan works. If there is no decision to be made against a document, it is training and should be labelled as such.
- **A technical simulation or red-team engagement:** executing attacks against systems tests controls, not decision-making. Running one and calling it a tabletop confuses two different assurance activities with different participants and different outputs.
- **A compliance checkbox:** an exercise conducted to satisfy an auditor, with the scenario written after the session and no participants who could disagree, produces a document rather than a finding. Recognise it and say so.
- **A live incident handled in a conference room:** if real systems are down, that is a response, not an exercise. Suspend the exercise, run the incident, and note what the unplanned event revealed.
- **A vendor demonstration:** a product walkthrough with a scenario the vendor wrote tests the product's narrative. It is not assurance about your plan.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER present an exercise as assurance that a capability works** — it demonstrates that a decision can be discussed, which is weaker and must be described accurately.
- **NEVER record a participant's performance as a finding about that individual** — findings attach to plans, tooling and authority, not to people.
- **NEVER use real customer data, live credentials or production systems in a tabletop scenario.**
- **NEVER close an exercise without owners and dates on every finding**, and never mark an action complete because a document was updated rather than because a test passed.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Objectives written before scenario:** each objective is stated, and each names the decision that would demonstrate it.
- [ ] **Traceability complete:** every objective has at least one inject that forces it, and every inject maps to an objective.
- [ ] **Plan version identified:** the exercise states which plan revision and which contract clauses it tests, with their dates.
- [ ] **Safety rules stated:** no-blame conduct, no live credentials, no production systems, and a facilitator stop authority.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: tabletop-exercise-design
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`incident-response-playbooks`](../incident-response-playbooks/SKILL.md) - Incident Response (flagship)
- [`ir-triage-and-timeline`](../ir-triage-and-timeline/SKILL.md) - Incident Response (core)
- [`containment-and-eradication`](../containment-and-eradication/SKILL.md) - Incident Response (core)
- [`ransomware-response`](../ransomware-response/SKILL.md) - Incident Response (flagship)
- [`business-email-compromise-response`](../business-email-compromise-response/SKILL.md) - Incident Response (core)
- [`post-incident-review-and-lessons`](../post-incident-review-and-lessons/SKILL.md) - Incident Response (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `tabletop-exercise-design` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **CISA CTEP alignment:** the CISA Tabletop Exercise Packages publish a situation manual, facilitator/evaluator handbook, exercise brief, feedback form and AAR/Improvement Plan template, and recommend drafting the AAR-IP within three to four weeks of conduct. Those artefacts are free and save design time; adapt rather than rebuild.
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 10 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/ctf_search (9), CYBER_CPT/cloudgoat (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 4 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
