---
name: denial-of-service-response
description: "Responds to denial of service: distinguishing volumetric from application-layer, mitigation options, provider coordination and business continuity decisions. Use when availability is under attack."
family: incident-response
tier: leaf
triggers: ["dos response", "ddos mitigation", "availability incident"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-125]
related: [incident-response-playbooks, ir-triage-and-timeline, containment-and-eradication, ransomware-response]
---

# Denial of Service Response - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Incident Response`](../README.md) | Tier: **leaf** | Paired Counterpart: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md)

## Mechanism and Preconditions

A denial-of-service incident is a capacity problem first and a security problem second, and the response method follows from that ordering. The three families exhaust different resources and therefore need different evidence and different owners. Volumetric floods exhaust bandwidth and packet-processing capacity on the transit path, before any application logic runs; the 2025 record event of 29.7 Tbps and 14.1 Bpps from the Aisuru IoT botnet used UDP carpet-bombing across roughly 15,000 destination ports per second with randomised packet attributes, which defeats per-flow and per-source controls by construction. Protocol-state floods exhaust connection and stream state — Rapid Reset abuses client-sent HTTP/2 stream resets (CVE-2023-44487) and MadeYouReset abuses server-provoked resets (CVE-2025-8671) — so the control is a limit on concurrent streams and control-frame rate rather than on request volume. Application-layer floods exhaust worker concurrency and origin egress, and are the family where a botnet sized below any per-client rate limit still saturates the origin. The precondition that decides whether any mitigation can work is topological: the traffic must traverse a control you own or rent. If the origin is directly reachable, if the DNS record leaks it, or if a legacy endpoint still answers on the pre-migration address, then the mitigation operates on a path the attacker is not using. The second precondition is measurement: without a same-hour baseline for the endpoint, the ASN mix and the cache-status ratio, a launch spike and a flood are indistinguishable in the first ten minutes.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the symptom is link saturation, packet loss or BGP churn **THEN** take the volumetric branch and engage the carrier or provider; **IF** bandwidth is flat while latency and error rate climb **THEN** take the application-layer branch and stop looking at the bandwidth graph.
2. **IF** throughput is flat but connection and frame counters spike **THEN** take the protocol-state branch and limit concurrent streams and control frames, because request-rate limits do not touch this family.
3. **IF** the origin answers on its address outside the mitigation path **THEN** fix shielding before anything else; every filter applied in front of a reachable origin is decorative and the dashboard will look healthy while the origin fails.
4. **IF** the flood sources are residential or IoT addresses shared with real users **THEN** prefer cache-shaping, challenge and rate classes over ASN blocking, and **IF** the addresses belong to a rented proxy pool **THEN** classify it as availability plus abuse, because wholesale blocking harms subscribers without stopping the operator.
5. **IF** the event exceeds contracted mitigation capacity **THEN** the decision moves to business continuity — degrade features, serve static, reduce scope — and it is a business decision to be made by the incident commander with measured numbers.
6. **IF** telemetry source covering `volumetric` / `application layer` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).
8. **IF** required preconditions for `denial-of-service-response` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need L7 mitigation engineering detail | [`botnet-and-application-ddos-mitigation`](../botnet-and-application-ddos-mitigation/SKILL.md) | Cache-key, JA3/JA4 and origin-shield specifics |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Evidence classes for classification and mitigation attestation |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Measurement and provider-coordination entry points |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm which measurement points exist and which are blind.** Traffic counters on the transit edge, flow records for the prefix, load-balancer request metrics, origin access logs and provider mitigation exports answer different questions. The origin-only view of a scrubbed flood shows nothing; the edge-only view of a direct-to-origin flood shows a healthy service.
2. **Classify by exhausted resource, then by path.** Volumetric, protocol-state, or application-layer; then whether the traffic traverses a control you own. Classify from counters, not from the alert title, and record the classification because each family has a different owner and a different stop condition.
3. **Measure against the same-hour baseline for that endpoint.** Compare request rate, ASN cardinality, user-agent cardinality, cache-status ratio and error rate for the current window against the same hour on prior weeks. The finding is the shape change: collapsing diversity with rising volume is a botnet; rising volume with stable diversity is demand.
4. **State the stop condition.** Stop when the origin's request rate, error rate and latency are back to the pre-incident baseline with mitigation still in place, and the mitigation path itself reports the drop. A provider event closing is not the stop condition, because a second vector frequently begins as the first ends.
5. **Prove the mitigation is in the path.** The proof is a provider mitigation record with an identifier overlapping the window, plus an origin ingress rate that falls in the same UTC minute. A filter that was deployed, a runbook that was executed, and a graph that recovered are three separate claims; only the paired evidence establishes causation.

## Concrete Patterns

| Indicator / Artifact | Evidence class | What it proves |
|---|---|---|
| Packets per second and bits per second on the transit interface with link utilisation | Router or flow telemetry | Which resource is exhausted: bandwidth saturates before any application metric moves |
| HTTP/2 `RST_STREAM` per connection and control-frame rate at the edge | Edge protocol telemetry | Protocol-state exhaustion; distinguishes reset floods from request floods and identifies the reset direction |
| Request rate per endpoint with ASN and user-agent cardinality | Edge analytics aggregation | Whether volume is diverse (demand) or concentrated (botnet), independent of absolute size |
| `cache_status` HIT/MISS ratio for the targeted endpoint | CDN access log field | Cache-bypass abuse when the ratio collapses on one endpoint while total volume is modest |
| Provider mitigation event with start, peak rate and dropped volume | Scrubbing provider export | The mitigation actually acted, as opposed to the attack having ended on its own |
| Origin ingress requests from addresses outside the published edge ranges | Origin access log or flow record | Whether the mitigation path is being bypassed entirely |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
# WEAK TRIAGE / RULE:
# Alert when requests per second exceed a fixed threshold on any endpoint.
# A product launch and a botnet both exceed it; the responder tunes the
# threshold upward after every launch until the alert is meaningless,
# and the first real flood is dismissed as "probably marketing".
```

**High-Signal Grounded Artifact:**

```kql
let base = CloudflareAccessLog
  | where TimeGenerated between (ago(8d) .. ago(1d))
  | summarize base_req = avg(req), base_asn = avg(asn), base_ua = avg(ua)
    by url_path, hour = hourofday(TimeGenerated);
CloudflareAccessLog
| where TimeGenerated > ago(60m)
| summarize req = count(), asn = dcount(client_asn), ua = dcount(user_agent),
            miss = avg(cache_status == "MISS")
  by url_path, hour = hourofday(TimeGenerated)
| join kind=inner base on url_path, hour
| extend req_ratio = req / base_req,
         diversity = (asn * 1.0 / req) / nullif(base_asn / base_req, 0.0)
| where req_ratio > 3 and diversity < 0.3 and miss > 0.8
| project url_path, req_ratio, diversity, miss, asn, ua
// Volume up, source diversity down, cache defeated: a flood, not a launch.
```

**Why this matters:** the detection is a ratio against the same hour on prior weeks plus a diversity collapse, so a launch (volume up, diversity stable) stays quiet while a botnet surge is separated from ordinary growth without anyone tuning a threshold.

## When It Is NOT This Issue

- **Product launch, sale or marketing campaign:** volume rises with stable or rising ASN and user-agent diversity and a healthy cache hit ratio, because real users request the same assets. Confirm against the campaign calendar before invoking procedure.
- **Upstream transit or peering fault:** loss and latency without a corresponding request-rate rise is routing, not load. Confirm with path measurement and the provider status feed.
- **Single retry-looping integration:** one client without backoff can saturate an endpoint at low overall volume. Distinct client count per endpoint separates it from a botnet.
- **Scraper traffic from residential proxies:** moderate per-client rates from consumer addresses is content and cost abuse rather than availability attack; treatment differs and blocking the ranges damages real subscribers.
- **Cache purge or deploy-induced thundering herd:** a mass invalidation reproduces the cache-bypass signature exactly. Diff the cache configuration change log against the onset minute.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `volumetric` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Measurement points enumerated:** transit, edge, load balancer and origin views were each confirmed to exist for the window, and any blind point is named rather than assumed quiet.
- [ ] **Resource classified:** the exhausted resource (bandwidth, protocol state, worker concurrency) was identified from counters and the classification recorded.
- [ ] **Baseline differential computed:** current values were compared against the same hour on prior weeks across volume, ASN diversity, user-agent diversity and cache status.
- [ ] **Path ownership confirmed:** whether the traffic traverses a control the organisation owns or rents was established, and origin reachability was tested from outside.
- [ ] **Mitigation attested:** a provider event identifier plus an origin-side ingress change in the same UTC minute, with the causation stated rather than inferred from recovery.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: denial-of-service-response
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

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `denial-of-service-response` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 21 |
| Distinct dataset sources | 10 |
| Top sources | CYBER_CPT/atomic_red_team (7), SecEval/attck (4), cyber-security/vulnerability-intelligence__mitre-attack-techniques.json (3), SecEval/owasp_mastg (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 3 det / 0 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
