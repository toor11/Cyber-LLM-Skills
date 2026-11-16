---
name: detection-as-code-and-testing
description: "Manages detections as code: version control, CI validation, automated rule testing and safe deployment pipelines. Use when scaling a detection program beyond manual rule editing."
family: detection-and-monitoring
tier: core
triggers: ["detection as code", "rule testing", "detection ci", "atomic test validation"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [detection-engineering, sigma-rule-authoring, yara-rule-authoring, siem-query-and-log-analysis]
---

# Detection As Code and Testing - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Detection and Monitoring`](../README.md) | Tier: **core** | Paired Counterpart: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md)

## Mechanism and Preconditions

Detection-as-code works because a rule has two distinct artefacts that can be verified separately: the *source* (the YAML or query text a human reviews) and the *compiled query* (what the backend actually executes). A pipeline that only lints the source verifies nothing the backend will run, and a pipeline that only deploys the compiled query has no reviewable provenance. The durable pattern therefore keeps the source in a repository, compiles it per backend as a build artefact, and attaches the compilation output to the commit so any deployed detection can be traced back to the exact text that produced it. Testing has three independent layers: a *positive fixture* (an event the rule must match), a *negative fixture* (a near-miss it must not match, usually the same event with one benign field different), and a *boundary fixture* (an event exactly at a numeric threshold). A rule that passes the positive test but fails the negative one is a rule that will page the SOC at 03:00, and a rule with no boundary fixture silently changes behaviour whenever someone edits a threshold. Correlation rules add a fourth layer, because their semantics are time-windowed: the fixture set must include a pair that falls outside the `timespan` as well as inside it, or the test passes for the wrong reason.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the repository holds only converted queries and no source **THEN** the pipeline has no reviewable origin; regenerate sources or declare the repo a deployment mirror, and do not describe it as detection-as-code.
2. **IF** the source is Sigma **THEN** the build must compile every rule for every declared backend and fail on any conversion error, keeping the output as an artefact; **IF** the source is backend-native (SPL, KQL, EQL) **THEN** lint and parse it with the backend's own tooling and still attach the deployed text to the commit.
3. **IF** a rule has only a positive fixture **THEN** it is untested for precision; add the near-miss negative before promoting it. **IF** the rule carries a numeric threshold **THEN** add the boundary fixture in the same change.
4. **IF** the rule is a Sigma correlation **THEN** fixtures must include an out-of-window pair and an in-window pair, and the test must assert both; **IF** the rule is single-event **THEN** one positive and one negative fixture are the minimum.
5. **IF** a fixture fails to parse into your event schema **THEN** the fixture is not exercising the rule; repair the fixture before interpreting the result, because a schema-invalid fixture that "passes" is matching on something unintended.
6. **IF** the deployment target exposes an API (saved-search endpoint, rule API, ARM template) **THEN** deploy through it with the commit hash embedded in the rule ID or description; **IF** the target is file-based **THEN** name the artefact after the commit and keep a copy.
7. **IF** telemetry source covering the fixtures' fields is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`; a fixture that cannot be expressed in the deployed schema is a mapping failure waiting to ship.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Fixture replay, deployment provenance, drift between source and deployed text |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Lint, multi-backend compile, artefact handling, API deployment |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| The rule must be proven to fire against real behaviour, not a fixture | [`atomic-red-team-validation`](../atomic-red-team-validation/SKILL.md) | Emulation, prereq gates, and cleanup discipline |
| A rule is noisy and the change must be attributable | [`alert-tuning-and-false-positive-reduction`](../alert-tuning-and-false-positive-reduction/SKILL.md) | Disposition-driven tuning and re-fire gates |

## Procedure

1. **Inventory the two artefacts for every rule.** For each detection, record where the source lives, which backends it compiles to, and where each compiled artefact is stored. A rule with a source but no stored compilation cannot be diffed against production, and that diff is the only proof the deployed query matches the reviewed text.
2. **Separate lint from compile from replay.** Lint validates structure and conventions; compile proves the source converts for every declared backend; replay proves the compiled query selects the positive fixtures and rejects the negatives. A gate that merges these stages cannot tell you which one failed.
3. **Build the fixture triple per rule.** Author the positive event, the near-miss negative that differs in exactly one benign dimension, and the boundary event when a numeric threshold exists. Store fixtures beside the rule with a schema-valid structure so a fixture that stops parsing fails the build loudly.
4. **Add the correlation fixture pair for windowed rules.** For every correlation rule, add one pair inside the `timespan` and one outside, and assert the outside pair does *not* fire. Without that assertion, a `timespan` misconfiguration passes every test.
5. **Define the promotion differential.** Compare the candidate against the currently deployed version on both fixture sets and on a fixed historical sample: hit count delta, negative-fixture behaviour, and any backend where compilation output changed materially. Promotion is blocked by a regressed negative, not by a hit-count change alone.
6. **Embed provenance in the deployment.** Stamp the commit hash into the rule identifier or description, attach the compiled artefact to the build, and record the deployment time. This is what makes the later question "which version produced this alert" answerable.
7. **Name the stop condition.** Stop and declare `Inconclusive` when the backend has no compile pipeline for the source dialect, when a fixture cannot be represented in the deployed schema, when the historical sample is retained for less than the comparison window, or when the deployed rule was changed outside the pipeline so provenance is broken.
8. **State what counts as proof.** Proof of a safe promotion is four artefacts from one commit: the reviewed source, the compiled query for each declared backend, the replay result across the fixture triplets, and the stamped deployment record. A green pipeline that produced none of these proves only that the script ran.

## Concrete Patterns

| Indicator / Artifact | Query class | What it proves |
|---|---|---|
| Compiled query text for each backend, stored as a build artefact keyed by commit | provenance | That a reviewer can diff what ships against what was reviewed; without it the pipeline is a deployer, not a control |
| Negative fixture result alongside the positive fixture result | fixture replay | That the rule distinguishes the behaviour from its near-miss; a passing positive with a firing negative is a precision defect shipping as a success |
| Correlation fixture pair outside the declared `timespan` | window assertion | That the time window is enforced, which no single-event fixture can test |
| Deployed rule text fetched from the backend compared with the built artefact | drift detection | That production matches the repository; manual edits and console hotfixes appear here first |
| Hit-count delta of the candidate rule against a fixed historical sample | regression | Whether the change alters selection on real telemetry, independent of the synthetic fixtures |
| Fixture parse result against the target event schema | schema conformance | That the fixture is expressible in the deployed field model; a fixture that fails to parse cannot test the rule it was written for |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```yaml
# CI job that proves the YAML is well-formed and then deploys it.
- run: sigma check rules/
- run: cp rules/*.yml /srv/detections/
# No compilation per backend, so a modifier the backend ignores ships silently.
# No fixtures, so a rule matching everything and a rule matching nothing
# both pass. No provenance, so a later alert cannot be traced to a commit.
```

**High-Signal Grounded Artifact:**

```yaml
name: detection-ci
on: [pull_request]
jobs:
  build-and-replay:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install sigma-cli
      - name: lint source
        run: sigma check rules/
      - name: compile every declared backend
        run: |
          set -e
          for backend in splunk sentinel elasticsearch; do
            mkdir -p build/$backend
            sigma convert -t "$backend" -p "$BACKEND_PIPELINE" rules/ > "build/$backend/queries.txt"
          done
      - name: replay fixtures (positive must hit, negative must not)
        run: python tests/replay_fixtures.py --rules rules/ --fixtures tests/fixtures/ --fail-on-negative-hit
      - uses: actions/upload-artifact@v4
        with:
          name: compiled-${{ github.sha }}
          path: build/
```

**Why this matters:** the strong form compiles each declared backend and keeps the output as an artefact tied to the commit, then evaluates both the positive and the negative fixture so a rule that matches everything is rejected; the weak form verifies YAML syntax and copies files, which passes equally for a rule that fires on all telemetry and one that can never fire.

## When It Is NOT This Issue

- **Fixture that no longer parses:** a schema change (a renamed ECS field, an ECS 9.0 removal such as `process.pgid`, an OCSF `tid` to `ptid` migration) leaves the fixture unparseable, and a test harness that skips unparseable fixtures reports green. Assert parse success explicitly.
- **Backend pipeline default differing from the test pipeline:** compiling with one pipeline in CI and another in production changes modifiers and field mappings, so the tested query is not the deployed query. Pin the pipeline name and version in both places.
- **Correlation rule tested as a single event:** a Sigma correlation's `timespan`, `group-by`, and referenced rule names are not exercised by replaying one event, so the rule appears correct while its window semantics are untested.
- **Console hotfix outside the pipeline:** an analyst edits a rule in the SIEM UI during an incident, and the repository no longer describes production. Compare deployed text against the built artefact on a schedule or the drift is invisible.
- **Historical sample shorter than the comparison window:** a replay over 24 hours of retention compared against a 30-day expectation measures retention, not the rule. Confirm the sample window before interpreting a hit-count delta.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a pipeline is safe because it is green when telemetry covering the rule's logsource was absent, rotated out, or unmapped in the test environment.**
- **NEVER describe a syntax check as validation, or a fixture-less replay as a test.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** the source repository, the per-backend compilation output, the fixture directory, and the deployment record location were all located and are keyed to the same commit.
- [ ] **Differential defined:** candidate versus deployed comparison covers the positive fixture, the negative fixture, the correlation window pair where applicable, and a fixed historical sample whose retention was confirmed.
- [ ] **Stop condition stated:** missing backend compiler, schema-inexpressible fixture, insufficient retention, or out-of-pipeline production edit is named as the reason for `Inconclusive` where it applies.
- [ ] **Proof standard met:** reviewed source, compiled artefact per declared backend, replay results across the fixture triplets, and a commit-stamped deployment record are all present for one commit.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: detection-as-code-and-testing
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Commit hash, backends compiled, pipeline names and versions, fixture set, historical sample window and retention, deployment record]
- **Behavioral Analysis**: [Positive, negative, boundary and correlation-window results; hit-count delta on the sample; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Deployed rule text fetched from the backend, drift against build artefact, second backend compile diff]
- **Containment / Detection / Hardening Action**: [Gate to add or repair, drift to reconcile, pipeline version to pin, owner and review date]
```

## Related Sub-Skills

- [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`detection-engineering`](../detection-engineering/SKILL.md) - Detection and Monitoring (flagship)
- [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`yara-rule-authoring`](../yara-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) - Detection and Monitoring (core)
- [`log-source-onboarding-and-parsing`](../log-source-onboarding-and-parsing/SKILL.md) - Detection and Monitoring (core)

## Operating Notes

- **Compile per backend, always:** a Sigma rule is a source format, not a query. The pipeline's value is the artefact it produces, and an artefact you cannot inspect is one you cannot review.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`); ATT&CK v18 detection strategies are a useful unit for grouping rules, since one analytic may satisfy several technique detections.
- **Safety & authorization:** Pipelines deploy detection content only; they must never modify logging configuration, disable a control, or hold credentials broader than the rule-deployment scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 17 |
| Distinct dataset sources | 12 |
| Top sources | OffsecCyber (4), CYBER_CPT/L5/ctf_search (2), CYBER_CPT/blackhills (2), cyber-security/security-code (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 11 cases |
| Grounding | multi-dataset corpus-grounded |
