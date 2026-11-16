---
name: c2-infrastructure-and-redirectors
description: "Designs and operates command and control infrastructure: domain and certificate selection, redirectors, CDN fronting, categorization, and resilience against blocking. Use when building sustained access."
family: network-ad-and-endpoint
tier: core
triggers: ["c2 infrastructure", "redirector", "c2 domain", "cobalt strike infrastructure", "domain fronting", "c2 opsec"]
cwe: [CWE-284]
owasp: []
attack: [T1090]
capec: [CAPEC-563]
related: [network-recon-and-port-scanning, service-enumeration, network-protocol-attacks, firewall-and-segmentation-testing]
---

# C2 Infrastructure and Redirectors - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **core** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

Command-and-control infrastructure is a resilience problem rather than a protocol problem: the operator needs a channel that survives blocking, and the defender needs a signal that survives domain rotation. Redirectors exist to keep the true endpoint out of the client's configuration, and their detection value is that a redirector's certificate, headers and timing often differ from the brand it imitates. The assessment question is which infrastructure patterns the estate's egress controls and proxy logs can actually observe.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the channel must survive domain blocking **THEN** domain fronting is largely dead at major CDNs; the pattern is now fast rotation across many cheap domains
2. **IF** the channel must survive IP blocking **THEN** a CDN-fronted or cloud-hosted endpoint with shared addressing is the usual choice, and its certificate is the tell
3. **IF** the question is whether the estate can see it **THEN** proxy logs and TLS metadata are the evidence; a channel over a permitted protocol is invisible to port-based controls
4. **IF** the objective is to detect rather than to build **THEN** the finding is the gap in egress visibility, not the infrastructure itself
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `c2-infrastructure-and-redirectors` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The implant's timing is the signal | [`c2-implant-and-beaconing`](../c2-implant-and-beaconing/SKILL.md) | Beacon periodicity and jitter |
| The channel is a DNS or ICMP tunnel | [`pivoting-and-tunneling-dns-and-icmp-tunnels`](../pivoting-and-tunneling-dns-and-icmp-tunnels/SKILL.md) | Covert channel mechanics |
| The channel is a SOCKS pivot | [`pivoting-and-tunneling-socks-and-port-forwarding`](../pivoting-and-tunneling-socks-and-port-forwarding/SKILL.md) | Traffic forwarding |
| The infrastructure is the entry point | [`initial-access-via-edge-devices`](../initial-access-via-edge-devices/SKILL.md) | Perimeter exposure |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Establish what egress visibility exists.** Proxy logs with full URLs, TLS metadata with SNI and certificate fields, DNS logs, and NetFlow. Each reveals a different fraction of a channel, and the combination decides what a finding can claim.
2. **Read the certificate and header profile of a candidate endpoint.** A redirector imitating a brand usually has a certificate issued recently, a generic issuer, and headers that do not match the brand's stack. These are visible from a single request and require no interaction with the implant.
3. **Define the differential between legitimate and covert traffic.** A legitimate SaaS endpoint has stable certificate fields, consistent response headers and predictable timing. The differential is a permitted protocol with an unexpected certificate profile or an implausible request cadence.
4. **Name the stop condition.** Stop at the first observed property that the estate's controls would miss: an encrypted channel over 443 with no SNI inspection, or a DNS tunnel the resolver logs but nobody queries.
5. **State the proof.** Proof is the endpoint's certificate and header profile, the protocol and port, and the specific visibility gap. An infrastructure diagram without the observation gap is not a finding about the estate.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Certificate issued within days for a lookalike name | Proves recently built infrastructure for the campaign, visible from the certificate alone; any TLS endpoint. |
| SNI present but no HTTP host inspection | Proves the proxy sees the destination name but not the request, a partial-visibility gap; enterprise proxy. |
| Beacon cadence with low jitter to one endpoint | Proves automated rather than human traffic, which is the timing signal; any egress path. |
| DNS queries for high-entropy subdomains under one parent | Proves a DNS tunnel or a domain-generation scheme; resolver logs. |
| Same IP serving many unrelated names | Proves shared redirector infrastructure, a common pattern with cloud-hosted endpoints; TLS and DNS logs. |

## Worked Contrast

**Weak configuration — egress permitted to any destination on 443 with no TLS inspection and no DNS logging:**

```bash
# firewall: any destination on 443 permitted; proxy: CONNECT allowed to any host;
# DNS: queries go to the ISP resolver and are not logged
# an encrypted channel to a rotated domain is invisible end to end
```

**Hardened configuration — default-deny egress with an allowlist and logged DNS:**

```bash
# firewall: permit 443 only to the categorised allowlist, log denies
# proxy: enforce CONNECT to the allowlist and record SNI and certificate subject
# DNS: forward through a logging resolver with response policy zones
# verification: a request to an unlisted destination is denied and the DNS query is recorded
```

**Why this matters:** covert channels survive because egress is permissive, so the controls are the allowlist, the proxy's metadata capture and DNS logging, verified by a denied request that still produces a log.

## When It Is NOT This Issue

- **A newly issued certificate on a legitimate service.** Certificate automation issues new certificates constantly; check the name against the inventory rather than the age alone.
- **A CDN fronting many unrelated names.** Shared addressing is the CDN model; the finding is a name that should not be behind that CDN.
- **Periodic traffic from a management agent.** Agents beacon by design; the baseline of sanctioned endpoints separates them from covert ones.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `c2-infrastructure-and-redirectors` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `c2-infrastructure-and-redirectors` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: c2-infrastructure-and-redirectors
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: T1090]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`firewall-and-segmentation-testing`](../firewall-and-segmentation-testing/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-enumeration`](../active-directory-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `c2-infrastructure-and-redirectors` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1090`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 9 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/blackhills (4), cyber-security/CyberSec-Dataset (2), CYBER_CPT/mitre_attack_enterprise (1), CYBER_CPT/expku (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
