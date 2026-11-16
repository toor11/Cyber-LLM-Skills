---
name: network-detection-and-ids
description: "Detects malicious network activity: IDS rule writing, traffic baselining, protocol anomaly detection and encrypted traffic analysis. Use when monitoring network traffic for threats."
family: detection-and-monitoring
tier: core
triggers: ["network detection", "ids rule", "suricata", "snort", "traffic anomaly"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [detection-engineering, sigma-rule-authoring, yara-rule-authoring, siem-query-and-log-analysis]
---

# Network Detection and IDS - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Detection and Monitoring`](../README.md) | Tier: **core** | Paired Counterpart: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md)

## Mechanism and Preconditions

A network IDS inspects packets and reassembled application-layer transactions against signatures and protocol parsers, then emits one alert record per matching transaction into `eve.json` (Suricata) or a unified2/fast record (Snort). Detection quality is bounded by what the sensor can actually reconstruct: a rule that matches on `http.uri` needs the HTTP parser to have claimed the flow, so an evasive client that fragments the header or speaks the same port with a different protocol produces no match while the traffic is still on the wire. Encrypted traffic removes payload inspection entirely and leaves the handshake — SNI, certificate, and the client fingerprint (JA3, and from Suricata 8 the JA4 family) — as the observable, which supports prevalence-based rather than signature-based detection. Baselining works on flow metadata (`conn.log`, NetFlow) and can prove a volume or periodicity shift but never content; the honest claim from flow data alone is "this conversation is unusual", not "this payload was malicious".

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the traffic is encrypted and no decryption or endpoint telemetry exists **THEN** restrict claims to handshake metadata and flow shape, and label the finding metadata-only; never report payload content you could not see.
2. **IF** the sensor is in IDS mode on a mirrored port or TAP **THEN** expect asymmetric routing and drops; **IF** `stats` shows capture-kernel drops above a small fraction, declare `INCONCLUSIVE (Sensor Drop)` before interpreting any absence.
3. **IF** the question is "did this rule fire" **THEN** take the signature branch and check `alert.signature_id` plus `rev`; **IF** it is "is this host behaving unusually" **THEN** take the baseline branch on flow records.
4. **IF** the rule needs `http.*`, `dns.*`, `tls.*` or `ja4.hash` **THEN** confirm the corresponding app-layer parser is enabled and the flow is not being handled by a fallback, or the rule can never match.
5. **IF** the environment terminates TLS at a proxy **THEN** the certificate and JA4 you observe belong to the proxy, not the client — attribute accordingly or the whole conclusion inverts.
6. **IF** telemetry source covering `Suricata` or `Snort` alerts, or the flow records behind the baseline, is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need alert, flow and protocol queries | [`QUERIES.md`](QUERIES.md) | Signature, baseline, handshake and drop classes |
| Need sensor and rule tooling | [`TOOLS.md`](TOOLS.md) | `suricata`, `snort`, `zeek`, `eve.json` inspection |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Block, sinkhole or monitor decisions per verdict |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Writing and linting Suricata rules | [`suricata-lua-and-rule-qa-tooling`](../../security-automation-and-tool-development/suricata-lua-and-rule-qa-tooling/SKILL.md) | Owned there: load gates, `sid` lint, PCAP regression harness |
| Computing or comparing client fingerprints | [`c2-traffic-analysis`](../../malware-analysis/c2-traffic-analysis/SKILL.md) | Owned there: JA4/JA4S/JARM derivation and prevalence method |
| Writing Zeek scripts rather than reading logs | [`zeek-script-and-notice-development`](../../security-automation-and-tool-development/zeek-script-and-notice-development/SKILL.md) | Owned there: script and notice framework authoring |

## Procedure

1. **Confirm the sensor's actual field of view.** Establish which interfaces are tapped, whether both directions are visible, which app-layer parsers are enabled, and the capture drop counters for the window. A signature rule and a baseline query have different tolerances for drops, so record this before either.
2. **Choose the branch from what the packets can support.** Signature branch for a known artefact or protocol violation, baseline branch for rate and periodicity questions, handshake branch for encrypted traffic. State the branch and its blind spot: the baseline branch cannot see content, the signature branch cannot see a behaviour no rule encodes.
3. **Define the baseline-versus-probe differential on the same key.** Use destination plus service, or client fingerprint plus SNI, and compare a quiet 14-day window against the probe window. A rare value is only interesting relative to its own prevalence, so print the prevalence alongside the finding.
4. **Name the stop condition.** Stop and declare `Inconclusive` when capture drops make the window incomplete, when the flow was handled by a fallback parser so the app-layer fields are absent by construction, when TLS termination moves the observable to a proxy, or when retention in the sensor's log store ends inside the window.
5. **State what counts as proof.** Proof is a signature alert with its `sid` and `rev` plus the matching flow record, or a baseline outlier reproduced in a second sensor or a second time window with the same key. A single alert with no corroborating flow is a rule event, not a confirmed conversation.

## Concrete Patterns

| Indicator / Artifact | Query class | What it proves |
|---|---|---|
| `event_type: alert` with `alert.signature_id` and `alert.rev` | signature | A specific rule revision matched a specific transaction; the `rev` makes the claim reproducible |
| `event_type: stats` `capture.kernel_drops` above threshold | sensor health | The window is incomplete, so any absence in it is unproven |
| `event_type: flow` bytes and packets grouped by destination and service | baseline | A volume or direction shift against the host's own history, independent of payload |
| `tls` record with `ja4` and `sni` prevalence | handshake | A rare client fingerprint paired with an SNI inconsistent with the same host's normal traffic |
| `dns` query name with unusual length or entropy distribution | protocol anomaly | Tunnelling-shaped naming rather than ordinary resolution, visible without decryption |
| `event_type: anomaly` or parser-specific `app_proto: failed` | parser | Traffic the engine could not classify, which is where signature rules silently stop matching |
| Same `flow_id` appearing as both `alert` and `flow` | correlation | The alert belongs to a real bidirectional conversation with byte counts, not to a stray packet |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
# WEAK: alert on any DNS query with a long label, counted once.
alert dns any any -> any any (msg:"Long DNS label"; dns.query; \
  content:!"."; sid:9000001; rev:1;)
# No threshold, no entropy, no prevalence, and no flow record attached.
# A CDN, an antivirus lookup, and a tunnel all look identical here.
```

**High-Signal Grounded Detection:**

```text
# STRONG: rarity is established first, then the signature is scoped to it.
# Step 1 (flow/DNS store): prevalence of the query name across the fleet
#   group by dns.rrname, count(distinct source.ip) as hosts
#   keep names where hosts <= 2 and the label length > 40
# Step 2 (eve.json): attach the conversations that carried those names
#   event_type: dns and dns.rrname in <rare set>
#   then join event_type: flow on flow_id for byte counts and duration
# Step 3: alert only where the same flow_id also shows a sustained,
#   near-constant inter-query interval, which ordinary resolution does not.
```

**Why this matters:** the weak rule fires on a shape that legitimate resolvers produce constantly, while the strong form establishes that the name is rare in this estate, ties it to the flows that carried it, and only then adds the periodicity that separates a beacon from a lookup — each step naming the artefact that supports it.

## When It Is NOT This Issue

- **Asymmetric routing and VLAN truncation:** a sensor on one leg of an asymmetric path sees requests without responses, so request-only rules match and response-dependent rules never do. The symptom is a rule that fires for some hosts and not others on the same path.
- **TLS interception moving the observable:** with a terminating proxy, every client presents the proxy's certificate and the proxy's JA4. A fingerprint investigation run without knowing this attributes proxy behaviour to hosts.
- **CDN and cloud fronting:** destination IPs and SNI rotate per request by design, so destination-based baselining produces constant outliers for ordinary browsing. Key on the registered domain, not the IP.
- **Scanner and load-test traffic:** an approved vulnerability scanner produces protocol violations and odd user agents across the whole estate in a short window. Confirm the scanner's source ranges before triaging.
- **Reassembly and evasion by design:** fragmentation, overlapping segments and TCP-level tricks can make a rule miss while the endpoint accepted the payload. A signature absence is not proof the endpoint did not receive the content.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `Suricata` or `Snort` was disabled, rotated out, or uncollected.**
- **NEVER claim payload content from flow-only or encrypted data** — say metadata-only and name what would be needed.
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** tapped interfaces, enabled app-layer parsers and capture drop counters were read for the window, not assumed.
- [ ] **Branch chosen:** signature, baseline or handshake branch was selected explicitly and its blind spot stated in the output.
- [ ] **Differential defined:** the same key was compared across a quiet window and the probe window, with prevalence printed next to every rare value.
- [ ] **Stop condition stated:** drops, fallback parsing, TLS termination and retention were each cleared or named as the reason for `Inconclusive`.
- [ ] **Proof standard met:** an alert with `sid` and `rev` is joined to its flow record, or a baseline outlier is reproduced in a second window or sensor.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: network-detection-and-ids
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

- **Know what you cannot see:** drops, encryption and asymmetric routing each remove evidence silently. Stating the blind spot is part of the finding, not a caveat around it.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; replaying captured traffic against a test rule set is safe, sinkholing a live destination is a change action.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 21 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/ctf_search (17), CYBER_CPT/oxdf (3), SecEval/attck (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
