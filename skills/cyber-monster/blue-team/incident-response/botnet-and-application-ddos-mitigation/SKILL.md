---
name: botnet-and-application-ddos-mitigation
description: "Responds to L3/L4 volumetric floods and L7 HTTP/2 Rapid-Reset or cache-bypass DDoS attacks: BGP Anycast/RTBH upstream scrubbing, JA3/JA4 + ASN/rate-limit WAF rules, origin IP shielding, and cache-key normalization to protect origin compute. Use during active DDoS mitigation."
family: incident-response
tier: core
triggers: ["ddos mitigation playbook", "l7 http flood defense", "origin ip shield", "cache bypass ddos"]
cwe: [CWE-400]
owasp: []
attack: []
capec: []
related: [incident-response-playbooks, ir-triage-and-timeline, containment-and-eradication, ransomware-response]
corpus_sparse: true
---

# Botnet and Application DDOS Mitigation - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Incident Response`](../README.md) | Tier: **core** | Paired Counterpart: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

A DDoS incident is a capacity-exhaustion event with two distinct physics. Volumetric floods are measured in bits and packets per second and saturate transit links before any application logic executes: the Aisuru IoT botnet drove a 29.7 Tbps / 14.1 Bpps UDP carpet-bombing attack in Q3 2025 that randomised packet attributes and hit roughly 15,000 destination ports per second, so per-flow ACLs and source-IP reputation are structurally useless against it. Application-layer floods consume worker concurrency and upstream egress while bandwidth graphs stay flat: HTTP/2 stream-reset abuse (client-sent resets in Rapid Reset, CVE-2023-44487, and server-provoked resets in MadeYouReset, CVE-2025-8671) and cache-bypass requests — randomised query strings that force a MISS on every call — push origin compute cost per unit of bandwidth up by orders of magnitude. Containability rests on one precondition that is usually the actual gap: the origin must accept traffic only from the mitigation path. If the origin IP is discoverable and directly reachable, the CDN or scrubbing centre in front of it absorbs nothing and the operator reads a healthy edge dashboard while the origin melts. Detectability rests on a second precondition: a per-ASN, per-endpoint and per-cache-status baseline for the same hour-of-week, plus HTTP/2 frame counters, because a botnet sized to stay under any per-client rate limit is invisible to fixed thresholds and obvious to a differential.

- **CWE-400 (Uncontrolled Resource Consumption):** The product does not properly control the allocation and maintenance of a limited resource.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the symptom is packet loss, link saturation or BGP churn **THEN** take the volumetric branch (upstream/transit, RTBH, scrubbing) and do not spend the first hour tuning WAF rules, which cannot act on traffic that never reaches the edge.
2. **IF** bandwidth is normal but p99 latency, 5xx rate or worker queue depth is climbing **THEN** take the application-layer branch: request-rate-per-endpoint, cache-status ratio and HTTP/2 stream-reset counters decide among cache-bypass, reset-flood and expensive-endpoint abuse.
3. **IF** the origin answers on its public address from a vantage point outside the mitigation path **THEN** treat origin shielding as the incident and fix it first — every mitigation applied in front of a directly reachable origin is decorative.
4. **IF** the flood carries residential or IoT source addresses that also serve legitimate users **THEN** prefer cache-shaping, challenge and rate classes over blanket ASN blocks, and **IF** the botnet is being rented as a proxy pool (Aisuru-class devices are resold as residential proxies) **THEN** classify the traffic as abuse plus availability, because blocking it wholesale damages real customers.
5. **IF** legal, insurance or law-enforcement engagement is required by contract or by the size of the event **THEN** open that track in parallel rather than after mitigation, since provider and carrier escalation queues are the long pole.
6. **IF** telemetry source covering `origin IP rotation` / `JA4 fingerprint rate limit` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).
8. **IF** required preconditions for `botnet-and-application-ddos-mitigation` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Establish which vantage points can actually see the traffic, and which cannot.** Enumerate edge/CDN request analytics with cache status, transit flow records for the same prefixes, origin ingress access logs, and provider mitigation events. Do this before forming a hypothesis: an edge-only view of a direct-to-origin flood shows nothing at all, and an origin-only view of a scrubbed flood shows a gap that looks like recovery.
2. **Branch on the shape of the exhaustion, not on the first alert.** Volumetric means bits and packets per second rise with link utilisation; application-layer means request rate per endpoint rises with worker or queue depth; protocol-level means connection and frame counters rise while payload volume does not. Record the branch taken, because each branch has different blind spots and a different owner (carrier vs edge vs application team).
3. **Build the differential before calling anything an attack.** Compare the current window against the same hour-of-week for the same endpoint, ASN mix, user-agent mix and cache-status ratio. A flood is a shape change — low ASN entropy, low client-behaviour diversity, high MISS ratio, high reset-per-connection — not merely a high number. A campaign spike and a product launch differ in diversity, not in volume.
4. **State the stop condition.** Stop when origin request rate and error rate return to the pre-incident baseline, direct-to-origin reachability is closed and verified from outside, and the mitigation path itself reports the drop — or when the provider confirms the event is larger than the contracted mitigation capacity, at which point the decision is business continuity (degrade features, serve static, reduce scope) rather than more filtering.
5. **Require proof that the action took effect, not that it was issued.** A WAF rule that was saved, an RTBH that was announced and a scrubbing runbook that was started are all claims. Proof is the provider mitigation event identifier plus an edge log line showing the challenge or block served, plus an origin ingress count that falls in the same UTC minute. If the origin still receives the traffic, the mitigation is not in the path.

## Concrete Patterns

| Indicator / Artifact | Evidence class | What it proves |
|---|---|---|
| Edge requests per second grouped by source ASN, joined to origin ingress rate for the same minute | Edge analytics plus origin access log | Proves absorption at the edge only when origin ingress falls as edge volume rises; equal growth in both means the mitigation path is bypassed |
| `cache_status` HIT/MISS ratio per endpoint on the CDN log | CDN access log field | A collapse from a stable hit ratio to near-total MISS on one endpoint proves cache-bypass by query-string randomisation rather than genuine new demand |
| HTTP/2 `RST_STREAM` count per connection and `GOAWAY` rate at the edge | Protocol telemetry or edge frame counters | High resets with flat bandwidth proves stream-reset abuse; the direction of the reset separates client-sent floods from server-provoked ones |
| Origin ingress requests whose source address is outside the published edge ranges | VPC flow logs or origin access log with real client IP preserved | Proves origin shielding failure and direct-to-origin traffic, i.e. that the CDN is not in the path |
| Provider mitigation event export (event id, start, peak PPS, drop volume) | Scrubbing or CDN mitigation log | Proves the provider actually dropped traffic during the window, rather than the graph dropping because the attacker stopped |
| Unique user-agent and ASN cardinality per thousand requests | Edge analytics aggregation | Low cardinality with high volume is botnet-like; high cardinality with high volume is a human event such as a launch or a sale |

## Worked Contrast

**Brittle / Single-Indicator or Missing-Telemetry Practice (`origin IP rotation`):**

```text
# ANTI-PATTERN: react to the first threshold breach on total requests per second.
# No cache-status split, no ASN cardinality, no origin ingress comparison.
# The 3am marketing email blast and a cache-bypass flood page identically,
# so the responder blocks ASNs and takes real customers down with the bots.
```

**Behavior-Anchored Detection & Guarded Triage (`origin IP rotation` — CWE-400):**

```kql
let baseline = toscalar(
    CloudflareAccessLog
    | where TimeGenerated between (ago(8d) .. ago(1d))
    | where url_path == "/api/v2/quote"
    | summarize avg(cache_status == "MISS") );
CloudflareAccessLog
| where TimeGenerated > ago(30m)
| where url_path == "/api/v2/quote"
| summarize req = count(),
            miss_ratio = avg(cache_status == "MISS"),
            asns = dcount(client_asn),
            uas = dcount(user_agent)
  by bin(TimeGenerated, 1m)
| where miss_ratio > 0.9 and miss_ratio > baseline * 5
| project TimeGenerated, req, miss_ratio, asns, uas
// Verdict requires origin ingress for the same minute to fall, not just edge volume.
```

**Why this matters:** Pairs `origin IP rotation` with `JA4 fingerprint rate limit` context, filters documented admin baselines, and enforces telemetry-presence verification.

## When It Is NOT This Issue

- **Planned launch, sale or ad campaign:** volume rises with ASN and user-agent cardinality and the cache hit ratio holds, because real users request the same assets. Check the change calendar and the referrer mix before escalating.
- **Crawler and AI-scraper traffic from residential proxies:** Aisuru-class devices are resold as residential proxy pools, so abuse arrives from consumer IPs at moderate per-client rates. This is content abuse and cost abuse, not an availability attack; blocking the ranges punishes real subscribers and does not stop the operator.
- **Cache purge, deploy or TTL misconfiguration:** a thundering herd after a mass invalidation reproduces a cache-bypass flood exactly — MISS ratio near 1.0, origin saturated — with no external actor. Diff the cache configuration change log against the onset minute.
- **Upstream carrier or transit incident:** packet loss and latency with flat or falling request counts is a routing or peering fault. Confirm with traceroute and the provider status feed before invoking DDoS procedure.
- **A single retry-looping integration:** one misconfigured client with retries and no backoff can saturate one endpoint at low volume. Look at the distinct client count per endpoint before treating it as a botnet.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `origin IP rotation` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Vantage points enumerated:** edge/CDN analytics, transit flow, and origin ingress were each confirmed to exist for the incident window, and any missing vantage point is named as a blind spot rather than assumed quiet.
- [ ] **Branch chosen and recorded:** the event was classified as volumetric, application-layer, or protocol-level from its shape, not from the alert name.
- [ ] **Differential computed:** current volume was compared with the same hour-of-week across ASN, user-agent and cache-status dimensions, and the finding is the shape change.
- [ ] **Origin reachability tested:** direct-to-origin access from outside the mitigation path was attempted and its result recorded before any claim of mitigation.
- [ ] **Effect proven by telemetry:** the mitigation is evidenced by a provider event identifier plus an origin ingress drop in the same UTC minute, not by the fact that a rule was saved.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: botnet-and-application-ddos-mitigation
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-400 / Domain Invariant]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `botnet-and-application-ddos-mitigation` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-400`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
