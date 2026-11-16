---
name: c2-implant-and-beaconing
description: "Operates implants and beacons: listener selection, sleep and jitter tuning, egress channel choice, task management and interactive shell upgrade. Use when maintaining interactive control of a host."
family: network-ad-and-endpoint
tier: core
triggers: ["c2 implant", "beacon", "implant operation", "cobalt strike beacon", "sliver", "havoc"]
cwe: [CWE-284]
owasp: []
attack: [T1071]
capec: [CAPEC-563]
related: [network-recon-and-port-scanning, service-enumeration, network-protocol-attacks, firewall-and-segmentation-testing]
---

# C2 Implant and Beaconing - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **core** | Paired Counterpart: [`dns-and-beacon-analytics`](../../../blue-team/detection-and-monitoring/dns-and-beacon-analytics/SKILL.md)

## Mechanism and Preconditions

A beacon is a periodic outbound connection whose timing, size and destination are controlled by the operator. Detection does not require knowing the protocol: periodicity and jitter are statistical properties, and a channel that checks in every sixty seconds with ten percent jitter is distinguishable from human traffic over a sufficient observation window. The defender's leverage is therefore the flow record rather than the payload, which is why beacon analysis works on encrypted traffic.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the connection is encrypted and the payload is opaque **THEN** timing and size are the only available signals; aggregate flows rather than inspecting content
2. **IF** the interval is irregular **THEN** jitter is itself a parameter; a distribution with a narrow mode and long tail is still machine-generated
3. **IF** the destination rotates **THEN** group by certificate or by ASN rather than by domain, since rotation defeats name-based grouping
4. **IF** the traffic is a legitimate agent **THEN** management agents beacon by design; the baseline of sanctioned endpoints is what separates them
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`dns-and-beacon-analytics`](../../../blue-team/detection-and-monitoring/dns-and-beacon-analytics/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `c2-implant-and-beaconing` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The infrastructure rather than the timing is the question | [`c2-infrastructure-and-redirectors`](../c2-infrastructure-and-redirectors/SKILL.md) | Certificates and hosting patterns |
| The channel is DNS | [`pivoting-and-tunneling-dns-and-icmp-tunnels`](../pivoting-and-tunneling-dns-and-icmp-tunnels/SKILL.md) | Resolver-level analysis |
| The traffic must be reconstructed from a capture | [`network-protocol-attacks-capture-and-intercept`](../network-protocol-attacks-capture-and-intercept/SKILL.md) | Packet-level evidence |
| The host side must be examined | [`host-persistence`](../host-persistence/SKILL.md) | What installed the beacon |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Aggregate flows by destination and source over a long window.** Beacon detection needs enough check-ins to establish a distribution. A window of hours is too short for a five-minute interval with jitter, so state the window and the minimum sample count.
2. **Compute the inter-arrival distribution, not the mean.** A mean interval close to a round number is suggestive; the distribution's shape is decisive. Low variance with occasional long gaps is the signature of jitter plus occasional failure.
3. **Establish a per-host baseline of sanctioned periodic traffic.** Patching agents, EDR heartbeats and monitoring all beacon. The differential is a periodic pattern to a destination that is not in the sanctioned set, which is why the baseline is the finding's foundation.
4. **Name the stop condition.** Stop at the first destination whose inter-arrival distribution is machine-like and which is not in the sanctioned set. Do not block based on a single flow, and do not attribute a family from timing alone.
5. **State the proof.** Proof is the inter-arrival statistics, the sample count, the window, and the destination's certificate or ASN. A single capture showing a connection is not a beacon finding.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Inter-arrival variance below a few percent at a round interval | Proves a scheduled check-in rather than human traffic; any egress path with flow records. |
| Payload sizes clustered in a narrow band | Proves a fixed-format check-in, which is visible even when encrypted; flow records with byte counts. |
| Destination grouped by certificate rather than name | Proves rotation against a stable backend, since the certificate is reused across domains; TLS metadata. |
| Beacon to a destination absent from the sanctioned agent inventory | Proves the pattern is not explained by management traffic, the actual finding; any estate with an agent inventory. |
| Jitter distribution with a long tail | Proves deliberate jitter plus occasional failure, which distinguishes a tool from a cron job; flow records. |

## Worked Contrast

**Weak configuration — no flow retention beyond 24 hours and no sanctioned-agent inventory:**

```bash
# NetFlow retention 24 hours, so a 10-minute beacon produces 144 samples and
# no baseline exists to compare it against; every periodic flow looks the same
nfcapd -t 60 -D -l /var/flows
# retention configured for one day only
```

**Hardened configuration — flow retention measured in weeks and a documented agent inventory:**

```bash
# retain flow records for at least 30 days, aggregate to 5-minute bins after 7 days
# maintain an inventory of sanctioned beaconing destinations per host role
# verification: a week-old beacon can be queried and its destination compared with the inventory
```

**Why this matters:** periodicity is only visible over a window longer than the interval, so the control is flow retention plus an inventory, verified by querying a week-old pattern.

## When It Is NOT This Issue

- **A sanctioned management agent.** Patching, EDR and monitoring agents beacon; the inventory is what distinguishes them.
- **A user with a periodic workflow.** Some business applications poll on a schedule; check the process and the destination category.
- **NTP or time synchronisation.** Fixed-interval traffic to a known time source is expected; the destination is the discriminator.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `c2-implant-and-beaconing` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `c2-implant-and-beaconing` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: c2-implant-and-beaconing
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: T1071]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`dns-and-beacon-analytics`](../../../blue-team/detection-and-monitoring/dns-and-beacon-analytics/SKILL.md) - Blue Detection/Defense Counterpart
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`firewall-and-segmentation-testing`](../firewall-and-segmentation-testing/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-enumeration`](../active-directory-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `c2-implant-and-beaconing` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1071`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 22 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/github_security_md (15), CYBER_CPT/gh_advisories (4), OffsecCyber (1), CYBER_CPT/netresec (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
