---
name: data-loss-prevention-monitoring
description: "Monitors for data exfiltration: DLP policy design, egress baselining, unusual transfer detection and alert triage. Use when protecting sensitive data from leaving the organization."
family: detection-and-monitoring
tier: leaf
triggers: ["dlp monitoring", "data exfiltration detection", "egress monitoring"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [detection-engineering, sigma-rule-authoring, yara-rule-authoring, siem-query-and-log-analysis]
corpus_sparse: true
---

# Data Loss Prevention Monitoring - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Detection and Monitoring`](../README.md) | Tier: **leaf** | Paired Counterpart: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Egress monitoring rests on a size asymmetry that no single sensor sees end to end. The DLP engine inspects content on channels it can decode (mail attachment, upload body, clipboard paste, print spool) and emits a verdict; the proxy or firewall records bytes and destination; the endpoint records the process that opened the file and the browser or client that carried it. A finding is the conjunction: a content verdict, a transfer volume that exceeds the actor's own baseline, and a process chain that explains how the content reached the channel. Two failure modes dominate. The first is coverage illusion: the engine is deployed on mail and web upload but not on personal cloud sync clients, SSH, or DNS, so egress through those channels produces no verdict at all and the absence reads as compliance. The second is baseline drift: roles differ by orders of magnitude in legitimate egress (a media engineer uploading rushes versus a finance analyst emailing a spreadsheet), so a global byte threshold either floods or blinds. The workable unit is per-identity and per-destination-class z-scoring against that identity's own trailing distribution, with content classification used to raise the score rather than to gate it — because classification rules are evaded by re-encoding, while a volume deviation from a principal's own history is not.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the sensitive data class is defined only by an engine policy that you cannot inspect **THEN** enumerate the engine's channel coverage and rule identifiers first; **IF** the channel in question has no DLP inspection point **THEN** report `Inconclusive (Channel Not Inspected)` and pivot to proxy or endpoint byte telemetry rather than concluding nothing left.
2. **IF** the destination is a corporate-sanctioned SaaS tenant **THEN** take the sanctioned-destination branch and evaluate the content verdict only; **IF** the destination is personal storage, a paste site, a webmail domain, or an unrecognised CDN **THEN** take the unsanctioned-destination branch, where a modest volume is already significant.
3. **IF** the question is "did sensitive content leave" **THEN** the evidence is the classifier verdict plus the transfer record; **IF** the question is "how much left" **THEN** only byte telemetry can answer it, and the classifier contributes nothing to the size estimate.
4. **IF** the actor is an automated pipeline or backup agent **THEN** baseline on the workload identity, not the human who owns it; **IF** the actor is a human on a managed device **THEN** baseline per identity per destination class over a trailing 30 days.
5. **IF** egress goes through an encrypted channel with no inspection point (personal VPN, SSH tunnel, sync client on a non-standard port) **THEN** the only available signals are volume, destination reputation, and endpoint file-access events; say so instead of reporting a content verdict you do not have.
6. **IF** a DLP alert fires on a document the user themselves authored and shared inside the tenant **THEN** it is a policy-scope question, not an exfiltration question; classify it as a tuning candidate and route it to [`alert-tuning-and-false-positive-reduction`](../alert-tuning-and-false-positive-reduction/SKILL.md).
7. **IF** telemetry source covering the channel is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
8. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Channel coverage audit, per-identity z-score, destination-class pivot |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Proxy log extraction, DLP verdict query, endpoint file-access join |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| The same actor also shows credential or token anomalies | [`identity-and-authentication-monitoring`](../identity-and-authentication-monitoring/SKILL.md) | Insider and token-theft cases read identity first |
| The transfer is DNS-shaped rather than HTTP upload | [`dns-and-beacon-analytics-dga-and-tunneling`](../dns-and-beacon-analytics-dga-and-tunneling/SKILL.md) | Label entropy and record-type analysis live there |

## Procedure

1. **Enumerate the inspection points before reading verdicts.** List every channel with a DLP decision point (mail gateway, CASB or proxy upload, endpoint agent, print, removable media) and the rule identifiers each applies. A channel with no entry is a blind spot, and it belongs in the answer as a stated limit rather than as a zero.
2. **Choose the evidence pair for the question asked.** For "did content leave", pair the classifier verdict with the transfer record keyed by request or message identifier. For "how much left", pair proxy or firewall bytes with the endpoint process. Never answer one with the other's evidence.
3. **Build the per-identity baseline on the trailing window.** Compute each identity's daily byte volume per destination class (sanctioned tenant, corporate service, unrecognised external) over 30 days, and keep the median and the median absolute deviation. Median-based dispersion survives the occasional legitimate large upload that a mean would smear.
4. **Score the probe window and rank by deviation, not by bytes.** A finance analyst tripling their usual 4 MB is a stronger signal than a media engineer sending 8 GB, which may be under their own median. Report the deviation and the absolute size side by side.
5. **Join the content verdict to the transfer and the process.** The classifier names the data class; the transfer record names the destination and size; the endpoint event names the file and the process that read it. Any two without the third is a lead.
6. **Name the stop condition.** Stop and declare `Inconclusive` when the channel has no inspection point, when the destination's egress path bypasses the proxy, when the identity has fewer than seven days of baseline, when the DLP verdict store retains less than the window, or when the transfer identifier cannot be joined across sources.
7. **State what counts as proof.** Proof is a classifier verdict naming a defined data class, a transfer record carrying that message or request identifier to a destination outside the sanctioned set, and an endpoint event showing the same principal reading a file of that class inside the transfer window. Two out of three is a lead with a named missing leg.

## Concrete Patterns

| Indicator / Artifact | Query class | What it proves |
|---|---|---|
| Channel inventory with DLP rule identifiers and last verdict timestamp per channel | coverage assertion | Which egress paths can produce a verdict at all; a channel with no rule cannot report exfiltration either way |
| Per-identity daily bytes to unrecognised external destinations, scored against median absolute deviation | deviation scoring | That this principal transferred more than their own history, which a fleet-wide threshold cannot show |
| DLP verdict joined to proxy request identifier | verdict-to-transfer join | That the content the classifier flagged is the content that left, rather than two unrelated events in the same hour |
| Endpoint file-read event for the flagged file, with the reading process | process attribution | How the content reached the channel; a browser upload without a file read suggests an already-staged copy |
| Distinct destination count per identity per day, including first-seen domains | novelty | First contact with a personal-storage or paste domain, which is significant at any volume |
| Removable-media write events correlated to the same identity and window | alternate-channel check | Whether the same data also left by a channel the DLP engine does not inspect |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
ALERT when outbound_bytes > 100MB in 24h
# One global number for every role, every destination, every protocol.
# Media, engineering and backup traffic trip it daily and are excluded by hand,
# which quietly widens the exclusion until the rule only fires on the loudest case.
# Nothing here inspects content, and nothing records which channel was even visible.
```

**High-Signal Grounded Artifact:**

```text
Per identity, per destination class, trailing 30 days:
  med   = median(daily_bytes)
  mad   = median(|daily_bytes - med|)
  score = (probe_bytes - med) / (1.4826 * mad)     for mad > 0
ALERT when score >= 6
      AND destination_class = 'unrecognised-external'
      AND dlp_verdict.data_class IS NOT NULL
Report: identity, score, probe_bytes, med, mad, data_class, transfer_id, process_name.
# The deviation is per principal, so role differences cancel.
# The content verdict raises confidence; the transfer record supplies the destination.
```

**Why this matters:** the strong form bounds the comparison to the principal's own history and destination class so role differences cancel, and it carries both the content verdict and the transfer identifier into the finding; the weak form uses one fleet-wide byte threshold that is either flooded by legitimate bulk traffic or narrowed by hand until it detects only the noisiest case.

## When It Is NOT This Issue

- **Backup, sync, or replication agents:** endpoint backup and sanctioned SaaS sync legitimately move the full dataset nightly under a service identity. Identify the agent's process and destination pair before scoring any volume, or the largest legitimate transfer of the day will rank first.
- **DLP engine policy recompiled mid-window:** a rule update or a new classifier release re-scores the same document class differently, producing a verdict spike with no change in user behaviour. Compare verdict counts against the policy version and its deployment time.
- **Proxy log sampling:** some proxies log a sampled percentage of connections under load, so byte totals under-report during peak traffic. A transfer during a sampled period cannot be sized from proxy logs alone; fall back to the firewall or NetFlow record.
- **Short baseline for a new joiner or role change:** an identity with fewer than seven days of history has an unstable median, so the z-score is meaningless. Treat the first weeks as an observation period and say so.
- **Sanctioned external collaboration:** an approved partner tenant or a customer-managed share is external by domain but sanctioned by policy. It belongs to the sanctioned destination class; excluding it is policy configuration, not tuning of the detector.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a user, host, or channel moved no data when the DLP engine had no inspection point on that channel or the proxy log was sampled.**
- **NEVER report a byte volume as a content finding, or a classifier verdict as a size estimate.**
- **NEVER recommend destructive containment (account disablement, device wipe, or legal escalation) before preserving the transfer records and confirming the data class with the data owner.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** every channel in scope was inventoried with its DLP rule identifiers and last verdict time, and the proxy or firewall record was confirmed to be unsampled for the window.
- [ ] **Differential defined:** per-identity, per-destination-class baseline over 30 days with median and median absolute deviation, compared against the probe window and reported alongside absolute size.
- [ ] **Stop condition stated:** uninspected channel, proxy bypass, baseline shorter than seven days, verdict-store retention, or unjoinable transfer identifier is named as the reason for `Inconclusive` where it applies.
- [ ] **Proof standard met:** classifier verdict naming a data class, transfer record carrying that identifier to an unsanctioned destination, and endpoint file-read event for the same principal; the missing leg is named if only two are present.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: data-loss-prevention-monitoring
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Channels with inspection points, DLP policy version, proxy or firewall record and its sampling state, UTC baseline and probe windows]
- **Behavioral Analysis**: [Per-identity deviation with median and MAD, destination class, data class from the verdict; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Endpoint file-read event and process, removable-media or alternate-channel check, destination reputation for first-seen domains]
- **Containment / Detection / Hardening Action**: [Channel to onboard, per-identity threshold to deploy, data-owner notification, transfer block sequenced after evidence capture]
```

## Related Sub-Skills

- [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`detection-engineering`](../detection-engineering/SKILL.md) - Detection and Monitoring (flagship)
- [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`yara-rule-authoring`](../yara-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) - Detection and Monitoring (core)
- [`log-source-onboarding-and-parsing`](../log-source-onboarding-and-parsing/SKILL.md) - Detection and Monitoring (core)

## Operating Notes

- **Coverage before verdicts:** a DLP programme that reports zero exfiltration usually has zero inspection points on the channels that matter. Publish the channel matrix beside every metric.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`); OCSF 1.6 class 2006 (Data Security Finding) is the portable shape when the engine's verdicts must be normalised.
- **Safety & authorization:** Read-only inspection of verdicts and transfer records; do not broaden a DLP policy, block a destination, or notify a data owner's manager without the data owner's classification and the privacy review that governs employee monitoring.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 2 |
| Distinct dataset sources | 2 |
| Top sources | cyber-security/CyberSec-Dataset (1), CYBER_CPT/nuclei_templates (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 1 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
