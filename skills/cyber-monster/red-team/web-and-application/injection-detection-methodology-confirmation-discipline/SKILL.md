---
name: injection-detection-methodology-confirmation-discipline
description: "Injection confirmation discipline. Covers proving an injection beyond a single anomaly: repeatability, control probes, isolating the parameter, and ruling out coincidence. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology."
family: web-and-application
tier: leaf
triggers: ["injection confirmation", "false positive injection", "prove injection"]
cwe: [CWE-20]
owasp: [A03:2021]
attack: []
capec: [CAPEC-248]
related: [injection-detection-methodology, injection-detection-methodology-parameter-mining, sql-injection, cross-site-scripting]
parent: injection-detection-methodology
corpus_sparse: true
---

# Injection Detection Methodology Confirmation Discipline - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

This leaf is the rigour layer that turns a suspicious response into a defensible finding or a dismissed coincidence. Its subject is not an interpreter but the measurement itself: a single anomaly can come from caching, load, retries, A/B logic, or jitter, so the discipline requires a controlled differential where exactly one variable changes and the effect both reproduces and reverts. It establishes a noise band from two independent benign controls, demands that the probe exceed that band, insists the differential disappears when the structural character is neutralised, and repeats enough times to separate signal from variance. The decision being made is epistemic: does the evidence isolate the injected variable as the cause. The practitioner gains confidence calibrated to the data and avoids reporting a non-finding. Proof is a reverting, repeatable, control-isolated differential, not the mere existence of a difference.

- **Precondition chain:** A candidate anomaly has been observed, a benign control and an escaped-probe control can both be issued, the environment's natural variation can be measured as a noise band, and the suspected effect can be made to appear and disappear by changing one variable.
- **Readable differential:** A probe response compared against two benign controls and an escaped-probe control; a finding stands only when the probe exceeds the control noise band and the escaped probe reverts to baseline, repeatably.
- **Empirical grounding:** CWE-20. This leaf concerns baseline-versus-probe rigour rather than a specific product bug; OWASP Top 10:2025 A05:2025 Injection is the parent category and SOURCES.md lists nothing discipline-specific, so it stays at the taxonomy level.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the candidate anomaly has not yet been placed in a class **THEN** start at parent class [`injection-detection-methodology`](../injection-detection-methodology/SKILL.md) first
2. **IF** a single response differed once and has not been reproduced **THEN** treat it as unconfirmed and build the control-isolated repeat before reporting
3. **IF** the only signal is elapsed time rather than content **THEN** switch to [`oast-and-blind-vulnerability-testing-timing-oracles`](../oast-and-blind-vulnerability-testing-timing-oracles/SKILL.md) for sample separation from jitter
4. **IF** no in-band signal exists and a callback is the only oracle **THEN** switch to [`oast-and-blind-vulnerability-testing-dns-and-http-callbacks`](../oast-and-blind-vulnerability-testing-dns-and-http-callbacks/SKILL.md) to attribute the hit to one request
5. **IF** the differential does not revert when the structural character is neutralised **THEN** reclassify as a logic, caching, or load effect rather than injection
6. **IF** the response varies even between two identical benign requests **THEN** raise the noise band and increase repeats before judging the probe
7. **IF** a shared cache may be serving the differential **THEN** vary a cache buster and confirm the effect survives cache isolation
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** the probe never exceeds the control noise band across repeats **THEN** STOP and record a verified non-finding rather than reporting the anomaly

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The anomaly is a measurable delay rather than a body change | [`oast-and-blind-vulnerability-testing-timing-oracles`](../oast-and-blind-vulnerability-testing-timing-oracles/SKILL.md) | Invariant is timing-sample separation from jitter, a dedicated oracle discipline |
| No in-band signal exists and a callback is the only oracle | [`oast-and-blind-vulnerability-testing-dns-and-http-callbacks`](../oast-and-blind-vulnerability-testing-dns-and-http-callbacks/SKILL.md) | Invariant is attributing an out-of-band hit to exactly one request |
| Need parent class methodology | [`injection-detection-methodology`](../injection-detection-methodology/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Restate the anomaly as a falsifiable hypothesis.** Write down the single variable you believe caused the observed difference and the exact channel it appeared on, so the test can isolate that one cause.
2. **Measure the noise band from two benign controls.** Issue two different benign values repeatedly and record the natural variation in status, length, and timing; this band is the floor any probe must clear to count.
3. **Add an escaped-probe control.** Prepare the same probe with its structural character neutralised server-side, because a true injection differential must vanish when that character can no longer change parse structure.
4. **Run the probe and the controls interleaved.** Alternate probe, benign, and escaped-probe requests to spread out caching and load effects rather than sending all probes together.
5. **Require reproduction across repeats.** Confirm the probe exceeds the noise band on a majority of runs, not once, so a lucky sample cannot carry the finding.
6. **Stop condition.** Halt when the evidence either (a) shows the probe exceeding the band while the escaped probe reverts, repeatably, (b) never clears the band or fails to revert, or (c) can be explained by a shared cache or retry that you cannot isolate. Case (a) confirms, (b) is a non-finding, (c) means suspend and remove the confound before judging.
7. **State what counts as proof.** Proof is a control-isolated, reverting differential reproduced across repeats, with the noise band, the escaped-probe revert, and the repeat count all recorded. A single divergent response, however striking, is not proof.
8. **Close by recording the confidence and the method.** Report the finding with its measured band, revert evidence, and repeat count, or record the dismissal with the same data, so the judgement is auditable. Verify by re-running the interleaved sequence once more.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Two identical benign requests that already differ in length or timing | Proves a wide noise band that must be measured first on any load-balanced or cached stack |
| A probe differential that persists after the structural character is neutralised | Proves the effect is not injection but logic, caching, or load, the key disconfirming signal |
| A single divergent response that never reproduces on repeat | Proves a coincidence or transient, not a confirmed candidate, on any backend |
| A timing difference smaller than the measured jitter across samples | Proves the signal is inside the noise band and cannot support a timing-oracle claim |
| A differential that disappears when a cache buster is added | Proves a shared cache, not the application, produced the observed difference |
| A probe effect that appears only when requests are batched together | Proves a concurrency or connection artefact rather than an input-driven differential |
| A reverting, repeatable differential isolated to one changed character | Proves a genuine candidate ready to route to the owning class skill |

## Worked Contrast

**Vulnerable pattern:**

```python
# Declares a finding from one response difference, with no control and no repeat
def is_injectable(base_resp, probe_resp):
    return probe_resp.elapsed != base_resp.elapsed   # any jitter trips this
```

**Hardened pattern:**

```python
def is_injectable(samples):
    # Require a reverting differential beyond a measured noise band, across repeats
    base = median(samples["control_a"] + samples["control_b"])
    noise = abs(median(samples["control_a"]) - median(samples["control_b"]))
    probe = median(samples["probe"])
    revert = median(samples["escaped_probe"])
    exceeds_band = abs(probe - base) > max(noise * 3, THRESHOLD)
    reverts = abs(revert - base) <= noise
    return exceeds_band and reverts
```

**Why this matters:** The naive check calls any single difference a finding, which is how noise becomes a false positive. The disciplined version only confirms when the probe exceeds a measured noise band and the escaped-probe control reverts to baseline, which isolates the injected variable as the cause.

## When It Is NOT This Issue

- **Single unreproduced anomaly:** one odd response that does not recur on repeat is a transient, not a confirmed injection.
- **Differential that fails to revert:** an effect that remains after neutralising the structural character is a different invariant, such as caching or logic.
- **Signal inside the noise band:** a length or timing change smaller than the variation between two benign controls is indistinguishable from jitter.
- **Cache-served difference:** a divergence that vanishes with a cache buster was produced by a shared cache, not the input.
- **Batch-only effect:** a differential that appears only when probes are sent together is a connection or concurrency artefact.
- **Retry or A/B artefact:** a difference traceable to automatic retries or experiment bucketing is not attributable to the probe.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `injection-detection-methodology-confirmation-discipline` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `injection-detection-methodology-confirmation-discipline` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: injection-detection-methodology-confirmation-discipline
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-20 | Mapping: A03:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`injection-detection-methodology`](../injection-detection-methodology/SKILL.md) - Web and Application (core)
- [`injection-detection-methodology-parameter-mining`](../injection-detection-methodology-parameter-mining/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `injection-detection-methodology-confirmation-discipline` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
