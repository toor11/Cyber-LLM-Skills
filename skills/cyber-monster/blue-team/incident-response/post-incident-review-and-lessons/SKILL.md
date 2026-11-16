---
name: post-incident-review-and-lessons
description: "Runs a blameless post-incident review: reconstructing what happened, identifying control and process gaps, and tracking remediation to closure. Use after containment and recovery."
family: incident-response
tier: core
triggers: ["post incident review", "lessons learned", "after action review"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [incident-response-playbooks, ir-triage-and-timeline, containment-and-eradication, ransomware-response]
---

# Post Incident Review and Lessons - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Incident Response`](../README.md) | Tier: **core** | Paired Counterpart: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md)

## Mechanism and Preconditions

A post-incident review converts an incident's timeline into changes that are owned, dated and testable. It works because it separates three questions that are usually conflated: what happened (an evidence question answered from logs), why the controls and the response behaved as they did (a systems question about defaults, alerts, runbooks and authority), and what will be different next time (an engineering question with a test attached). NIST SP 800-61r3 reorganised this as continuous improvement under CSF 2.0's Identify function, ID.IM-01 through ID.IM-04, rather than a terminal phase: lessons that are clear during response should be captured then and acted on immediately, not held for a single meeting after recovery. The precondition that makes a review useful rather than therapeutic is a shared UTC timeline marked confirmed versus inferred, plus a blameless framing that holds — a review where one role is implicitly on trial produces defensive accounts and hides the systemic cause, which is usually the one worth fixing. The failure mode to design against is the "lessons noted, not learned" backlog, where action items accumulate and quietly go stale because nobody owns them and nothing tests them.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the incident is still active or recovery is incomplete **THEN** capture the clear lessons now and schedule the formal review after recovery; do not hold a fix that is needed today for a meeting next month.
2. **IF** the incident timeline contains inferred timestamps **THEN** label them in the review record and state what would have made them confirmed; an action item often exists in that gap itself.
3. **IF** a single individual's action is the apparent cause **THEN** ask what tooling, default, alert or runbook made that action reasonable at the time, and write the action against that — the individual is a symptom of the system.
4. **IF** the same root cause has appeared in a previous incident **THEN** escalate it as a program-level finding with the earlier action item referenced; recurrence is evidence that the earlier action was not verified.
5. **IF** the review covers a regulated incident **THEN** keep the technical review and the legal or regulator-facing narrative separate, and let counsel review the technical record before it is circulated.
6. **IF** detection timing is in question **THEN** measure the intervals from the reconstructed timeline — dwell, time to detect, time to triage, time to contain, time to recover — and read the trend across incidents rather than any single value.
7. **IF** telemetry covering the incident is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` for that interval and make the onboarding an action item.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need the timeline, interval and action evidence classes | [`QUERIES.md`](QUERIES.md) | Interval measurement, contributing-factor joins, action verification |
| Need timeline and tracking tooling | [`TOOLS.md`](TOOLS.md) | Timesketch, action-register querying, trend analysis |
| Need the review sequence and closure criteria | [`PLAYBOOK.md`](PLAYBOOK.md) | Conduct order, blameless framing, verification |
| Need real-world case cards | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Timeline provenance in dispute | [`ir-triage-and-timeline`](../ir-triage-and-timeline/SKILL.md) | The confirmed-versus-inferred record |
| Review of an exercised capability | [`tabletop-exercise-design`](../tabletop-exercise-design/SKILL.md) | Objective and inject records to compare against |
| Obligation and disclosure handling | [`legal-and-regulatory-notification`](../legal-and-regulatory-notification/SKILL.md) | Separating the technical record from the legal narrative |

## Procedure

1. **Confirm the evidence source for the timeline before discussing causes.** Collect the confirmed-versus-inferred timeline from triage, the response actions with their timestamps, and the decision records. State which intervals are unprovable and why. A review that opens with "what went wrong" before establishing what is known will substitute recollection for evidence within ten minutes.
2. **Choose the branch from what the review is for.** Control branch when the question is why detection or prevention failed — the output is detection engineering and configuration change. Process branch when the question is why the response took as long as it did — the output is runbook, authority and communication change. Recurrence branch when a prior action was closed and the cause returned — the output is a verification failure finding, not a new action.
3. **Define the contributing-factor differential across incidents.** For each factor identified, ask whether it also existed in a comparable incident that went better, and whether it exists in the current design for systems that were not affected. A factor present in both the failed and the successful case is context, not cause.
4. **Bound the review and name the stop condition.** State the incidents in scope, the participants, and the closure criteria for each action. Stop and declare `Inconclusive` on root cause when the decisive interval is outside retention, when the decision record does not exist, when the only account is a participant's recollection contradicted by the log, or when the review is being used to assign fault rather than to change a system.
5. **State what counts as proof.** Proof of a root cause is a mechanism demonstrated against the timeline: a specific control, default or decision that produced the observed outcome, reproducible or corroborated by two sources. Proof that an action worked is a re-run of the failed scenario, an injected test event that fires the new detection, or an exercise that uses the updated runbook. An action is closed when its test passes, not when its ticket closes.

## Concrete Patterns

| Indicator / Artifact | Evidence class | What it proves |
|---|---|---|
| Interval set from the reconstructed timeline (dwell, detect, triage, contain, recover) | timeline measurement | Where response time was actually spent, as opposed to where participants believe it was |
| Decision record with timestamp, role and information available at the time | process record | Whether a delay was an authority gap, an information gap or a capacity gap |
| Control configuration state at the time of the incident | configuration record | Whether a control was absent, misconfigured or simply did not cover the path used |
| Prior incident with the same contributing factor and its closed action | recurrence record | That a previous action was marked complete without verification |
| Telemetry gap covering a decisive interval | coverage record | That a conclusion cannot be drawn, which is itself an action item |
| Re-run or injected test result for a completed action | verification record | That the fix works, which is the only closure evidence that counts |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
# WEAK: a review that produces narrative and a list of good intentions.
"Root cause: user clicked a link. Lessons: improve awareness training.
 Actions: strengthen security culture. Status: closed."
# No timeline, no interval measured, no owner, no test, and a cause that explains nothing.
```

**High-Signal Grounded Artifact:**

```text
PIR IR-2026-0417 — extract from the review record (all times UTC, source-linked)

INTERVALS (from confirmed timestamps only)
  T0 first malicious execution   2026-11-09 18:20:07  EDR pid record
  T1 first detection             2026-11-11 09:14:02  alert 88f2
  T2 human acknowledgement       2026-11-11 09:31:40  ticket comment
  T3 containment effective       2026-11-11 11:05:12  last write event
  dwell = 39h; detect = 39h; triage = 17m; contain = 1h34m

CONTRIBUTING FACTORS (tested against a comparable incident that went better)
  F1  egress inspection absent on the segment        present in both cases -> context, not cause
  F2  service account could write to the backup tier present only in the failed case -> CAUSE
  F3  alert routed to a queue with no rota           present only in the failed case -> CAUSE

ACTIONS (owner, date, verification test)
  A-01 Remove backup-tier write from svc-sql        DBA lead   2026-12-01  Attempt write after change; must fail with 403
  A-02 Route this alert class to the 24x7 rota      SOC mgr    2026-11-28  Inject a test alert; acknowledged <10m
  A-03 Onboard egress inspection on this segment    Netsec     2027-01-15  Replay recorded beacon; must alert

GAPS (declared, not inferred)
  T0-T1 interval depends on EDR retention of 30d; confirmed.
  Change record for the backup-tier grant not located -> F2 origin unproven.
```

**Why this matters:** the strong form measures intervals from confirmed timestamps, tests each contributing factor against a comparable case so context is separated from cause, and gives every action a verification test a reviewer can run; the weak form names a symptom as a cause, produces actions nobody owns, and closes them without evidence.

## When It Is NOT This Issue

- **A technical post-mortem with no process review:** a review that only maps ATT&CK techniques answers what the actor did, not why the organisation responded as it did. Both are needed, and conflating them leaves the response gaps unfixed.
- **A disciplinary investigation:** if the purpose is to determine whether a person acted improperly, that is an HR or legal process with different rules and different protections. Running it as a post-incident review in parallel destroys the review's usefulness.
- **A regulatory narrative:** the technical record and the regulator-facing account have different audiences and different constraints. Writing one document for both produces a record that serves neither and may conflict with counsel's advice.
- **A single-incident metrics exercise:** one incident's duration is noise. Reading a trend requires successive incidents measured the same way; a review that declares improvement from one data point is measuring enthusiasm.
- **A review of an incident that was never contained:** if containment is ongoing, the review is premature. Capture the clear lessons now and hold the formal review until the state is stable.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER present an inferred timestamp as confirmed**, and never publish an interval built on one without labelling it.
- **NEVER attribute a root cause to an individual** — attribute it to a control, default, alert, runbook or authority gap that a change could fix.
- **NEVER mark an action complete because a document was updated or a ticket closed** — closure requires the verification test to pass.
- **NEVER conclude an interval was clean when telemetry covering it was absent** — the correct finding is a coverage gap with an action item.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Timeline evidenced:** every timestamp used is marked confirmed or inferred, with its source, and unprovable intervals are declared.
- [ ] **Factors tested:** each contributing factor was checked against a comparable case or an unaffected system, and context is separated from cause.
- [ ] **Actions testable:** every action has one accountable owner, a date, and a verification method that is a test rather than a review.
- [ ] **Blameless framing held:** no finding attributes cause to an individual; each names a system condition a change could address.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: post-incident-review-and-lessons
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`incident-response-playbooks`](../incident-response-playbooks/SKILL.md) - Incident Response (flagship)
- [`ir-triage-and-timeline`](../ir-triage-and-timeline/SKILL.md) - Incident Response (core)
- [`containment-and-eradication`](../containment-and-eradication/SKILL.md) - Incident Response (core)
- [`ransomware-response`](../ransomware-response/SKILL.md) - Incident Response (flagship)
- [`business-email-compromise-response`](../business-email-compromise-response/SKILL.md) - Incident Response (core)
- [`tabletop-exercise-design`](../tabletop-exercise-design/SKILL.md) - Incident Response (leaf)
- [`legal-and-regulatory-notification`](../legal-and-regulatory-notification/SKILL.md) - Incident Response (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `post-incident-review-and-lessons` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Detection-continuity check:** where Defender XDR tables stream to the Microsoft Sentinel data lake, Defender retains 30 days while the lake can retain far longer, and lake-only tables are invisible to Sentinel analytics rules and the Logs blade. A review that needs a 90-day interval must query the lake directly or state the interval as unprovable.
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 12 |
| Distinct dataset sources | 10 |
| Top sources | CYBER_CPT/L5/ctf_search (3), OffsecCyber (1), bug-bounty-pentest-en (1), CYBER_CPT/L5/awesome_list (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 10 cases |
| Grounding | multi-dataset corpus-grounded |
