---
name: sigma-rule-authoring-cloud-and-network-rules
description: Sigma rules for cloud and network sources. Covers Sigma log sources for cloud audit logs, proxy and DNS telemetry, and their field mapping constraints. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: detection-and-monitoring
tier: leaf
triggers: ["sigma cloud", "sigma network", "sigma proxy"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [sigma-rule-authoring, sigma-rule-authoring-windows-event-rules, detection-engineering, yara-rule-authoring]
parent: sigma-rule-authoring
---

# Sigma Rule Authoring Cloud and Network Rules - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Detection and Monitoring`](../README.md) | Tier: **leaf** | Paired Counterpart: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md)

## Mechanism and Preconditions

Cloud and network logsources differ from endpoint ones in three ways that break copied rules. First, the event model is a service-plus-operation pair (`product: aws`, `service: cloudtrail` with `eventSource` and `eventName`) rather than a fixed event ID, so a rule must select on operation names that vary across provider API versions. Second, the payload is deeply nested JSON whose field paths differ per provider and per log type: a proxy rule keyed on `cs-host` and a Zeek rule keyed on `query` live in the same category name but never match the same document. Third, and most consequential, coverage is gated by a subscription rather than by a parser — AWS data events for S3 objects and DynamoDB are off by default, so the CloudTrail rule can be perfect and still have no events to evaluate. Network-side, a proxy may be configured to log only certain categories, and DNS logging may exist on the resolver but not in the pipeline. The rule author's obligation is to name the exact operation or field, and to state which subscription must be enabled for the rule to have input at all.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match `sigma-rule-authoring-cloud-and-network-rules` **THEN** start at parent class [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) first.
2. **IF** the rule targets a cloud data-plane operation **THEN** confirm the data-event subscription exists before authoring; **IF** it does not, the rule is `Inconclusive (Telemetry Gap)` regardless of its quality.
3. **IF** the same semantic exists in proxy, DNS and flow logs **THEN** author separate rules per logsource rather than one rule with a broad field list, because the pipelines map them onto different fields.
4. **IF** the selection depends on a nested JSON path **THEN** verify the path against a captured event from that provider and log type, not against documentation for a different service.
5. **IF** the operation set is long or version-dependent **THEN** use a wildcard on the operation name only where the provider's naming is stable, and list the exceptions in `falsepositives`.
6. **IF** telemetry source covering `CloudTrail`, `proxy` or `DNS` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) | General class triage before variant specifics |
| Need cloud and network rule checks | [`QUERIES.md`](QUERIES.md) | Operation enumeration, field path and subscription classes |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | `sigma convert` for cloud pipelines, provider CLI probes |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Endpoint event IDs instead of operation names | [`sigma-rule-authoring-windows-event-rules`](../sigma-rule-authoring-windows-event-rules/SKILL.md) | Different event model entirely |
| Network alert triage rather than rule authoring | [`network-detection-and-ids`](../network-detection-and-ids/SKILL.md) | Sensor position and baseline method live there |

## Procedure

1. **Confirm the subscription and the field paths before writing a selection.** Pull one real event from the provider's log store for the exact service and log type, and read the actual JSON keys. Then check whether the operation you intend to detect is even captured at that tier: management events and data events are separately subscribed for most providers.
2. **Choose the branch: control-plane, data-plane, or network-metadata.** Control-plane rules select on operation names and identities. Data-plane rules need a bucket or table scope and are usually volume-limited. Network-metadata rules select on proxy action, DNS record type, or flow shape and cannot see payload at all.
3. **Define the baseline-versus-probe differential per principal or per domain.** Convert the rule, then compute hits per `userIdentity` or per registered domain over a quiet 14-day window versus the probe window. Cloud estates have heavy legitimate automation that dominates absolute counts, so the per-principal delta is the only usable measure.
4. **Name the stop condition.** Stop when the operation is not captured at the subscribed tier, when the field path differs from the one captured, when the provider renamed the operation in a newer API version, when the pipeline maps the service but drops the nested object, or when the network log is sampled such that a low-volume event cannot be proven absent.
5. **State what counts as proof.** Proof is a converted rule that fires on a captured event of the exact service and log type, plus a confirmed subscription and a quiet-window count for the same principal or domain. A rule validated against documentation rather than a captured event has proven only its syntax.

## Concrete Patterns

| Indicator / Artifact | Query class | What it proves |
|---|---|---|
| `eventSource` plus `eventName` pair from a captured event | operation enumeration | The exact operation names the rule may select, and whether they are version-stable |
| Account-level trail configuration with data-event selectors | subscription | Whether the operation the rule targets produces events at all |
| Field path resolved against the captured JSON | field path | That the selection addresses a key that exists for this provider and log type |
| Per-`userIdentity` hit count over quiet versus probe window | baseline differential | Whether the rule's noise comes from automation rather than from the detection logic |
| Proxy action field distribution for one rule | network metadata | Whether the rule keys on an action the proxy actually records, rather than one it only enforces |
| DNS record type and response code for a queried name | DNS telemetry | Whether the rule can distinguish a resolution from a failure or a block |
| Same domain across proxy and DNS logsource | cross-logsource | That two independent sources saw the same destination, which a single logsource cannot show |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```yaml
# WEAK: one rule for three log types, keyed on a field none of them share.
title: Suspicious Cloud Or Web Activity
logsource:
  category: proxy
detection:
  sel:
    eventName|contains:
      - 'Delete'
      - 'Stop'
    url|contains: 'suspicious'
  condition: sel
# CloudTrail has no 'url'; the proxy has no 'eventName'. The rule can only ever
# match in a synthetic lab, and the data-event subscription question is unasked.
```

**High-Signal Grounded Artifact:**

```yaml
title: CloudTrail Trail Logging Stopped
id: 4d1c2a90-71b4-4e36-9c02-5f8a3d6e2b47
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'cloudtrail.amazonaws.com'
    eventName:
      - 'StopLogging'
      - 'DeleteTrail'
      - 'UpdateTrail'
  condition: selection
falsepositives:
  - Central logging team reconfiguring the organisation trail during a maintenance window
level: high
tags:
  - attack.defense-impairment
  - attack.t1685
---
title: Proxy Denied Request Followed By Allowed Retry Same Host
id: 8e3f5b21-6c47-4a19-b8d5-0e2c9a7f4d63
status: experimental
logsource:
  category: proxy
detection:
  selection:
    c-uri|contains:
      - '../'
      - '%2e%2e'
  filter_benign:
    sc-status: 200
  condition: selection and not filter_benign
level: medium
```

**Why this matters:** the weak rule merges a control-plane event model with a proxy field and can only match by accident. The strong pair names one service and its exact operations for the audit rule, and keeps the proxy rule on fields the proxy actually emits, with the benign-success case implemented as a filter rather than left as prose. It also tags the logging-disable behaviour against the post-v19 technique rather than the retired one.

## When It Is NOT This Issue

- **Data events not subscribed:** S3 object-level and DynamoDB item-level operations are not captured unless a data-event selector exists. The rule is correct and permanently silent.
- **Organisation trail versus account trail:** a rule expecting organisation-wide coverage finds only the accounts the trail actually includes; a missing account looks exactly like no activity.
- **Proxy logging configured for enforcement, not recording:** many proxies log only blocked transactions by default. An "allowed request" rule has no input while the block rule works fine.
- **Provider operation renaming:** cloud APIs add and rename operations between versions, so a rule listing explicit names silently stops covering the new path while continuing to fire on the old one.
- **DNS sampling and caching:** a resolver that logs only cache misses will not show repeated lookups, and a low-volume query cannot be proven absent from a sampled feed.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER invent provider operation names, field paths or Sigma service identifiers** — read them from a captured event or the provider's own log record.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `CloudTrail`, `proxy` or `DNS` was disabled, rotated out, or uncollected.**
- **NEVER claim payload content from proxy metadata fields alone** — a URL and a status code are not a request body.
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** a real event from the exact service and log type was captured and read, and the subscription tier was checked.
- [ ] **Branch chosen:** control-plane, data-plane or network-metadata was selected, and the rule uses only fields that branch actually emits.
- [ ] **Differential defined:** converted-rule hits compared per principal or per domain between a quiet 14-day window and the probe window.
- [ ] **Stop condition stated:** unsubscribed tier, differing field path, renamed operation, dropped nested object or sampling was named where it applied.
- [ ] **Proof standard met:** the converted rule fires on a captured event of that exact type, with the subscription and quiet-window count recorded.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: sigma-rule-authoring-cloud-and-network-rules
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`sigma-rule-authoring-windows-event-rules`](../sigma-rule-authoring-windows-event-rules/SKILL.md) - Detection and Monitoring (leaf)
- [`detection-engineering`](../detection-engineering/SKILL.md) - Detection and Monitoring (flagship)
- [`yara-rule-authoring`](../yara-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) - Detection and Monitoring (core)

## Operating Notes

- **Subscription before syntax:** in cloud log sources the most common reason a good rule never fires is that the operation was never being recorded. Check that first.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; reading trail configuration and captured events is safe, changing a trail's selectors is a change action.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 10 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/ctf_search (5), CYBER_CPT/gh_advisories (2), CYBER_CPT/atomic_red_team (1), CYBER_CPT/blackhills (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 4 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
