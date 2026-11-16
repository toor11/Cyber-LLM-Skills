---
name: detection-engineering-rule-lifecycle
description: "Detection rule lifecycle management. Covers the full rule lifecycle: proposal, authoring, testing, deployment, tuning, retirement and documentation. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology."
family: detection-and-monitoring
tier: leaf
triggers: ["detection lifecycle", "rule retirement", "rule governance"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [detection-engineering, detection-engineering-behaviour-to-observable, sigma-rule-authoring, yara-rule-authoring]
parent: detection-engineering
---

# Detection Engineering Rule Lifecycle - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Detection and Monitoring`](../README.md) | Tier: **leaf** | Paired Counterpart: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md)

## Mechanism and Preconditions

A detection rule is a small piece of software whose correctness decays for reasons outside its own text: the sensor it reads changes version, the schema renames a field, the benign population shifts as the estate adopts a new tool, and the adversary's variation drifts. Lifecycle management is the set of states a rule moves through with an explicit decision and evidence at each transition — proposed, authored, tested, deployed, tuned, and retired — plus a recorded owner and review date. The failure that makes lifecycle work necessary is *silent persistence*: a rule that no longer fires because its field moved, or fires on everything because its benign population grew, keeps sitting in the catalogue looking like coverage. Retirement is the state teams skip, and skipping it has a measurable cost — a stale rule consumes review attention, inflates coverage counts, and, when it fires rarely and wrongly, teaches analysts that the alert source is unreliable. The lifecycle therefore needs a staleness clock and a retirement test, not just a promotion gate: a rule with no disposition in its review window must be replayed against its positive fixture to distinguish "rare behaviour" from "cannot fire", and that replay result is the evidence that decides keep, tune, or retire.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match `detection-engineering-rule-lifecycle` **THEN** start at parent class [`detection-engineering`](../detection-engineering/SKILL.md) first.
2. **IF** the rule is entering the catalogue **THEN** apply the promotion gate (positive, negative, sample, mapping); **IF** the rule is already deployed **THEN** apply the review gate (disposition history, fixture replay, staleness clock). The two gates answer different questions and must not be merged.
3. **IF** a rule has fired in its review window and its dispositions are recorded **THEN** the decision is keep or tune, and the evidence is the disposition rationales; **IF** it has not fired at all **THEN** replay its positive fixture before deciding, because "rare" and "broken" look identical in the alert store.
4. **IF** the mapped technique or strategy was removed or restructured in a framework release **THEN** re-map before retiring; a rule can be correct while its `attack` reference is now invalid, and retiring on that basis loses real coverage.
5. **IF** two rules detect the same analytic **THEN** keep the one with better sampled precision and retire the other with a note pointing at the survivor; **IF** they cover different platforms **THEN** keep both and record the platform split.
6. **IF** the rule's owner has left or the owning team was reorganised **THEN** the rule is orphaned: assign an owner in the same review or retire it, because an unowned rule has no one to notice its decay.
7. **IF** telemetry source covering the rule's artifact is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`detection-engineering`](../detection-engineering/SKILL.md) | Claim structure and coverage before lifecycle decisions |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Staleness clock, orphan detection, fixture replay, duplicate coverage |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Repository history, catalogue export, replay harness |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| The observable behind the rule must be re-derived | [`detection-engineering-behaviour-to-observable`](../detection-engineering-behaviour-to-observable/SKILL.md) | Sensor inventory, field survival, documented losses |
| The rule needs automated gates rather than a manual review | [`detection-as-code-and-testing`](../detection-as-code-and-testing/SKILL.md) | Fixtures, compilation artefacts, drift checks |

## Procedure

1. **Reconstruct the rule's state from evidence, not from the ticket.** Pull the rule's git history, its deployment timestamp, its last disposition, and its mapped strategy. A rule whose history and deployment disagree is in an unknown state and the first action is to reconcile them.
2. **Separate the three review questions.** Does it still fire (fixture replay)? Does it fire usefully (sampled precision)? Is anyone still accountable for it (owner and review date)? A rule can pass one and fail the others, and each failure has a different remedy.
3. **Run the staleness clock.** Compute days since last disposition and days since last review. A rule past its review interval with no dispositions is either rare or broken, and only the fixture replay distinguishes them.
4. **Run the retirement test.** Replay the positive fixture against the deployed rule text and confirm the artifact still exists on the current sensor build. A rule whose fixture no longer fires is broken regardless of how recently it was reviewed; a rule whose artifact no longer exists is unmaintainable.
5. **Choose one transition and record its evidence.** Keep (replay passed, precision acceptable, owner assigned), tune (precision poor but behaviour still relevant), re-map (framework changed), or retire (duplicate, unmaintainable, or the behaviour is no longer reachable). Record the evidence for exactly one transition per change.
6. **Check the duplicate set before retiring.** Two rules covering the same analytic are a candidate for consolidation, but only after comparing their sampled precision on the same window; consolidating on the noisier rule is a coverage regression.
7. **Name the stop condition.** Stop and declare `Inconclusive` when the rule's deployed text cannot be recovered, when the fixture set is absent so replay is impossible, when the review window's dispositions are missing, or when the mapped technique was restructured and the mapping cannot be resolved without a framework decision.
8. **State what counts as proof.** Proof of a lifecycle transition is four fields on one record: the deployed rule hash, the fixture replay result, the sampled precision figure or an explicit "not measurable", and the named owner with a next review date. A transition without those four is an opinion held in a meeting.

## Concrete Patterns

| Indicator / Artifact | Query class | What it proves |
|---|---|---|
| Days since last disposition and days since last review, per rule | staleness clock | Which rules are drifting out of the review process; the leading indicator before a silent failure |
| Positive fixture replay result against the deployed rule text | retirement test | Whether the rule can still fire at all, which the alert store cannot distinguish from rare behaviour |
| Rules whose `owner` field is empty or points at a departed account | orphan detection | Rules nobody will notice decaying; ownership is the precondition for every later transition |
| Two rules with the same strategy/analytic pair and overlapping host sets | duplicate coverage | Candidates for consolidation, ranked by sampled precision rather than by age |
| Rule `attack` references that no longer resolve in the current framework release | mapping validity | Whether the rule's taxonomy claim is still true after a framework restructure |
| Deployment timestamp versus repository commit time | provenance | Whether production text matches reviewed text, which is the precondition for trusting any replay |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
Review meeting, quarterly:
  "Rule set: 412 rules. Keep them all, nothing came up."
# No fixture replay, so the 40 rules whose field was renamed last release
# are indistinguishable from the 372 that work.
# No owner check, so the 60 rules owned by leavers stay in the catalogue.
# No duplicate check, so two rules for the same analytic both page the queue.
# The count went up, which is reported as progress.
```

**High-Signal Grounded Artifact:**

```text
For each rule in the catalogue, compute one lifecycle row:
  deployed_hash      = sha256(deployed rule text fetched from the backend)
  last_disposition   = max(alert.disposition_time) over 90 days
  days_stale         = now - last_disposition        (null => never fired)
  fixture_replay     = PASS | FAIL | NO_FIXTURE
  sampled_precision  = 1 - fp/judged over 30 days     (null when judged < 20)
  owner, next_review = from the catalogue

Transition chosen by rule:
  retire     when fixture_replay = FAIL and the artifact is gone from the sensor build
  re-map     when the attack reference no longer resolves
  tune       when sampled_precision < 0.5 and fixture_replay = PASS
  keep       when fixture_replay = PASS and precision acceptable and owner is set
  escalate   when fixture_replay = NO_FIXTURE (author the fixture before deciding)
```

**Why this matters:** the strong form produces one evidence row per rule so every transition is supported by a replay result and a precision figure rather than by attendance, which makes "broken" distinguishable from "rare" and "unowned" visible before it becomes silent; the weak form confirms the catalogue size and reports growth as health.

## When It Is NOT This Issue

- **Fixture replay failing because the fixture is stale:** a schema migration can break the fixture and the rule together, or break only the fixture. Confirm the artifact still exists on the current sensor build before concluding the rule is broken.
- **Disposition field populated by case closure, not judgement:** some platforms write a default disposition on close, so "has a disposition" is not the same as "was judged". Check that the disposition carries a rationale rather than a system default.
- **Framework restructure mistaken for technique removal:** ATT&CK v19 merged several defense-evasion techniques into a new parent, so a rule referencing a now-merged technique is not obsolete — it needs re-mapping, and retiring it would drop real coverage.
- **Rule quiet because the sensor stopped delivering:** a rule whose logsource stopped arriving looks identical to a rule that cannot fire. Check logsource health before the retirement test, or the test result reflects a pipeline outage.
- **Duplicate consolidation on the wrong rule:** retiring the higher-precision rule because the other is newer is a coverage regression with a clean audit trail. Rank by sampled precision on the same window.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER retire or keep a rule when telemetry covering its artifact was disabled, rotated out, or uncollected.**
- **NEVER report a rule as healthy on the strength of its presence in the catalogue; a rule that cannot fire is not coverage.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** deployed rule text, git history, disposition store, fixture set, and sensor build were all located, and the deployed hash was computed rather than assumed.
- [ ] **Differential defined:** fixture replay result and sampled precision are both reported for the same rule version over the same window, with "not measurable" stated explicitly where the sample is too small.
- [ ] **Stop condition stated:** unrecoverable deployed text, absent fixtures, missing dispositions, or unresolved framework mapping is named as the reason for `Inconclusive` where it applies.
- [ ] **Proof standard met:** deployed hash, replay result, precision figure or explicit non-measurability, and a named owner with a next review date are all present on one record.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: detection-engineering-rule-lifecycle
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Rule ID and deployed hash, sensor build, disposition window and count, fixture set, mapped strategy and analytic]
- **Behavioral Analysis**: [Replay result, sampled precision or reason it is unmeasurable, staleness clock, duplicate set; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Second rule covering the same analytic with its precision; logsource health check behind a silent rule]
- **Containment / Detection / Hardening Action**: [Single transition with its evidence, owner assignment, next review date, replacement analytic if retiring]
```

## Related Sub-Skills

- [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`detection-engineering`](../detection-engineering/SKILL.md) - Detection and Monitoring (flagship)
- [`detection-engineering-behaviour-to-observable`](../detection-engineering-behaviour-to-observable/SKILL.md) - Detection and Monitoring (leaf)
- [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`yara-rule-authoring`](../yara-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) - Detection and Monitoring (core)

## Operating Notes

- **One transition per record:** a review that keeps, tunes, and re-maps in one change cannot be attributed when the alert volume moves. Split the changes.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`); a lifecycle review is the natural point to re-validate ATT&CK references after a version change, since merged and renamed techniques break mappings silently.
- **Safety & authorization:** Lifecycle work is documentation and replay only; never disable a rule in production as part of a review until its replacement is deployed or the coverage gap is accepted in writing.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 15 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/blackhills (7), CYBER_CPT/awesome_web_security (5), CYBER_CPT/ctf_search (2), CYBER_CPT/github_security_md (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 9 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
