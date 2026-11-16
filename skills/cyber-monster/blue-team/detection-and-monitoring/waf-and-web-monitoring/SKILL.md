---
name: waf-and-web-monitoring
description: "Monitors web traffic for attacks: WAF log review, attack pattern recognition, tuning blocked versus allowed rules and identifying successful bypasses. Use when defending web applications."
family: detection-and-monitoring
tier: leaf
triggers: ["waf monitoring", "web attack detection", "waf log analysis"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [detection-engineering, sigma-rule-authoring, yara-rule-authoring, siem-query-and-log-analysis]
---

# WAF and Web Monitoring - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Detection and Monitoring`](../README.md) | Tier: **leaf** | Paired Counterpart: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md)

## Mechanism and Preconditions

A WAF verdict is a comparison between what the engine parsed and what the origin server later executed, and the interesting cases live in the gap between those two. The engine inspects one interpretation of the request — after its own normalisation, decoding and body handling — while the origin has its own parser, framework routing and encoding rules. CRS 4 expresses detection as anomaly scoring: individual rules contribute a score, the inbound and outbound thresholds decide the action, and `tx.blocking_paranoia_level` selects which rule set contributes at all, with `tx.detection_paranoia_level` allowing higher-PL rules to log without scoring. A bypass is therefore usually a parser differential, not a missing signature: the payload that reached the application differs from the payload the engine scored. Monitoring requires the request as the engine saw it, the score and which rules fired, and the origin's own access log for the same request, because a blocked request has no origin entry and an allowed request leaves two records to reconcile.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the question is "was this attack blocked" **THEN** reconcile the WAF record against the origin access log for the same request; **IF** there is an origin entry for a request the WAF says it blocked, the block did not take effect.
2. **IF** the engine is CRS 4 **THEN** read `tx.blocking_paranoia_level` before judging a miss; a rule that exists at PL3 contributes nothing at PL1, and that is a configuration answer, not a detection gap.
3. **IF** the payload sits in the URL path rather than a query or body argument **THEN** check the rule family's targets explicitly — CRS 4.30.0 added `REQUEST_FILENAME` to the 932 family precisely because path-borne command injection was uninspected.
4. **IF** the site sits behind a CDN or a second proxy **THEN** confirm which layer produced the log and which layer's client IP is recorded, or every source-based conclusion is wrong.
5. **IF** the request was allowed with a nonzero anomaly score **THEN** treat it as the interesting population: it means the engine saw something and the threshold did not act.
6. **IF** telemetry source covering `WAF log`, `blocked request` or the origin access log is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need score, rule and reconciliation queries | [`QUERIES.md`](QUERIES.md) | Action, score, paranoia and origin-reconciliation classes |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | CRS setup inspection, `modsec` log reading, request replay |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Virtual patch, threshold change or block decision |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Application-layer response rather than edge tuning | [`web-application-incident-response`](../../incident-response/web-application-incident-response/SKILL.md) | Owned there: webshell discovery and access-log exploitation analysis |
| Rule engineering for CRS itself | [`waf-and-modsecurity-crs-rule-engineering`](../../security-automation-and-tool-development/waf-and-modsecurity-crs-rule-engineering/SKILL.md) | Owned there: writing and validating the rules |

## Procedure

1. **Confirm which layer logged what.** Establish the request path through CDN, load balancer, WAF and origin, and which of them records a verdict versus only an access line. Then confirm the client-IP field is the real client and not the upstream proxy, or every per-source conclusion is invalid.
2. **Choose the branch: blocked-volume, allowed-with-score, or origin-only.** Blocked volume measures rule efficacy. Allowed-with-score is where bypasses hide. Origin-only means the request never reached the WAF at all — a path, a hostname, or a protocol the edge does not terminate.
3. **Define the baseline-versus-probe differential per endpoint and rule family.** Compare the per-`REQUEST_URI`-path and per-rule-ID counts between a quiet 14-day window and the probe window. A spike in one rule family on one path is the signal; total blocked volume mostly tracks scanner traffic.
4. **Name the stop condition.** Stop when the origin log is unavailable for reconciliation, when the engine's log level omits the request body or the matched rule IDs, when the site is behind a layer whose logs you cannot read, when paranoia level makes the rule family inert, or when retention ends inside the window.
5. **State what counts as proof.** Proof is a blocked request with its WAF record and no matching origin entry, or an allowed request with a nonzero score whose origin entry shows the same payload executing. A WAF record alone cannot distinguish a block that worked from one that did not take effect.

## Concrete Patterns

| Indicator / Artifact | Query class | What it proves |
|---|---|---|
| Action value plus total anomaly score per request | verdict | Whether the engine acted and at what score, which the action flag alone hides |
| Matched rule IDs per request | rule attribution | Which rule families fired, so a miss can be attributed to paranoia level rather than a missing rule |
| WAF record joined to origin access log on method, path and timestamp | reconciliation | Whether the block took effect, since a blocked request leaves no origin entry |
| Allowed requests with score above zero | bypass candidate | Traffic the engine saw and the threshold let through, which is where parser differentials live |
| `tx.blocking_paranoia_level` reported with each engine instance | configuration | Whether the rule family under discussion could contribute at all on that host |
| Request path payloads against the rule family's targets | coverage | Whether path-borne payloads are inspected, which query and body inspection does not cover |
| Same request seen by two layers with different verdicts | differential | A layer that is not enforcing, or a second path that bypasses the WAF |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
# WEAK: count blocked requests and call it monitoring.
blocked_by_hour = count(action == "blocked") by hour
# Rises whenever a scanner sweeps the estate and falls when the scanner stops.
# Says nothing about what got through, and nothing about whether a block
# actually stopped the request from reaching the application.
```

**High-Signal Grounded Detection:**

```text
# STRONG: reconcile the verdict against the origin, then look at what passed.
step 1  waf:    request_id, method, path, status_action, score_total, rule_ids
step 2  origin: method, path, status, timestamp, upstream_ip, bytes
step 3  join on (method, normalised path, +-2s):
          left_only   -> engine blocked and origin never saw it  (block effective)
          matched     -> engine allowed it and origin served it  (verify payload)
step 4  filter: score_total > 0 and status_action == "allowed"
        group by path and rule family, compare against the 14-day baseline
# The finding is a path whose allowed-with-score count rose, not total volume.
```

**Why this matters:** the weak form measures the scanner's schedule. The strong form joins two independent logs so a block is proven to have taken effect, then focuses on the population the engine flagged but did not stop — which is the only place a bypass is visible.

## When It Is NOT This Issue

- **Scanner sweeps:** an internet-facing WAF always sees automated scanning. Blocked volume tracks the scanner, so a spike without a corresponding allowed-with-score change is background noise.
- **Paranoia-level inertness:** a rule at PL3 contributes zero score at PL1. A "miss" against a published CRS rule is often a configuration statement, not a detection failure.
- **Body inspection disabled for the content type:** multipart uploads and some JSON payloads are not inspected unless the engine is configured for them, so a payload in a form field is invisible by design rather than by defect.
- **CDN caching serving a response the origin never generated:** the origin access log has no entry because the request never reached it, which looks identical to a successful block.
- **Origin-side normalisation after inspection:** an application that decodes a parameter twice can execute a payload the engine scored on its first decode. Correct scoring plus correct blocking still yields a bypass.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER invent CRS rule IDs, paranoia levels or variable names** — read them from the deployed `crs-setup.conf` and the engine's own log.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `WAF log` or the origin access log was disabled, rotated out, or uncollected.**
- **NEVER claim payload content the engine did not log** — say which log level would be required and that it is not enabled.
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** the request path through CDN, load balancer, WAF and origin was mapped, and the client-IP field was verified against it.
- [ ] **Branch chosen:** blocked-volume, allowed-with-score or origin-only was selected, with the engine's paranoia level read for that host.
- [ ] **Differential defined:** per-path and per-rule-family counts compared between a quiet 14-day window and the probe window.
- [ ] **Stop condition stated:** missing origin log, insufficient log level, unreadable layer, inert paranoia level or short retention was named.
- [ ] **Proof standard met:** a block is shown to have no origin entry, or an allowed request's origin entry shows the same payload executing.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: waf-and-web-monitoring
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`detection-engineering`](../detection-engineering/SKILL.md) - Detection and Monitoring (flagship)
- [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`yara-rule-authoring`](../yara-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) - Detection and Monitoring (core)
- [`log-source-onboarding-and-parsing`](../log-source-onboarding-and-parsing/SKILL.md) - Detection and Monitoring (core)

## Operating Notes

- **Reconcile before concluding:** a WAF verdict is one side of a two-sided claim. The origin log is what turns "the engine blocked it" into "the request did not reach the application".
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; replaying a request against a staging copy is safe, raising a blocking threshold in production is a change action.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/nuclei_templates (2), CYBER_CPT/go_exploitdb (2), cyber-security/CyberSec-Dataset (1), CYBER_CPT/gh_advisories (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
