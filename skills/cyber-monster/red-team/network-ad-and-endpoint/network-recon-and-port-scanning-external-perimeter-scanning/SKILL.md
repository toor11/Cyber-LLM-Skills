---
name: network-recon-and-port-scanning-external-perimeter-scanning
description: "External perimeter scanning. Covers internet-facing discovery: ASN and netblock mapping, subdomain and certificate transparency correlation, and scan etiquette against production edge. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology."
family: network-ad-and-endpoint
tier: leaf
triggers: ["external scan", "asn mapping", "internet facing recon", "perimeter scan"]
cwe: [CWE-284]
owasp: []
attack: [T1046]
capec: [CAPEC-116]
related: [network-recon-and-port-scanning, network-recon-and-port-scanning-internal-network-mapping, service-enumeration, network-protocol-attacks]
parent: network-recon-and-port-scanning
---

# Network Recon and Port Scanning External Perimeter Scanning - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

External scanning measures what an unauthenticated internet source can reach, which is a different measurement from internal scanning because the path crosses provider filtering, CDN fronting and NAT. The unit of proof is the triple of source address, destination service and observed response. Because a single vantage point can be intercepted by a WAF, a geo-block or a sinkhole, perimeter exposure claims require a second independent source and a protocol-level response rather than a bare handshake.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the exposed range is unknown **THEN** enumerate owned netblocks and certificate names first, then scan; an IP list without an ownership record cannot support a finding
3. **IF** a host answers differently from two vantage points **THEN** record both observations and treat the difference as the finding, since asymmetric provider filtering is itself an exposure property
4. **IF** the port answers but the application returns a generic error page **THEN** fingerprint the fronting layer before claiming the backend service is exposed
5. **IF** the question is whether an internal foothold can reach the same service **THEN** switch to [`network-recon-and-port-scanning-internal-network-mapping`](../network-recon-and-port-scanning-internal-network-mapping/SKILL.md)
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `network-recon-and-port-scanning-external-perimeter-scanning` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need the full port inventory of one host | [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) | Base scan semantics and rate limits |
| Reachability must be proven from inside | [`network-recon-and-port-scanning-internal-network-mapping`](../network-recon-and-port-scanning-internal-network-mapping/SKILL.md) | East-west path differs from the internet path |
| A port turns out to be a directory service | [`service-enumeration-ldap-and-directory`](../service-enumeration-ldap-and-directory/SKILL.md) | Unauthenticated LDAP answers are their own evidence class |
| Boundary claim is the deliverable | [`firewall-and-segmentation-testing`](../firewall-and-segmentation-testing/SKILL.md) | Proves the rule, not just the port |
| Need the class-level branch table first | [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Establish ownership of the address range.** Reconcile the target list against RIR records, ASN announcements and certificate transparency names before scanning. Scanning an address you cannot tie to the client is both a scope breach and an unreliable finding, because the host may have changed tenants.
2. **Scan from two networks you control.** A commercial VPS and a residential or mobile egress produce different answers for the same target. Divergence isolates provider-level filtering from host-level filtering, which is the difference between 'the service is down' and 'the service is unreachable from your country'.
3. **Compare against an unauthenticated control request.** Send one benign HTTP GET and one protocol-correct request. A 403 from a CDN edge and a 200 from the origin are different exposures; the control request tells you which layer answered.
4. **Stop on provider abuse signals.** Abort when you see a scan-block page, a 429 with a retry-after, or an abuse notification. Continuing past that point converts an assessment into a nuisance and can invalidate the engagement.
5. **State what proves exposure.** A service is externally exposed when an independent source completes a protocol exchange that only that service could produce, and the response body or banner identifies the same product as the internal inventory record.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `nmap -sS -Pn --source-port 53 -p 443` | Proves whether provider filtering, not the host, controls reachability; Linux. Source-port manipulation only tests misconfigured ACLs and belongs in authorised boundary tests. |
| Certificate transparency name list | Proves which hostnames the organisation actually published, independent of DNS; any platform, via `crt.sh` queries. Names here that resolve to the scanned range are in scope candidates. |
| `curl -sSI https://host --resolve host:443:IP` | Proves which layer answers, CDN or origin, by pinning name to IP; cross-platform. The `server` and `via` headers identify the fronting product. |
| Two-vantage differential | Proves asymmetric filtering: one source gets SYN-ACK, the other silence; cross-platform. This is the only reliable evidence for geo or provider-level blocks. |
| `nmap --script ssl-cert -p 443` | Proves the certificate subject and SAN list behind the port; Linux. A certificate naming an internal hostname is a separate finding from the open port. |

## Worked Contrast

**Weak configuration — management interface published to 0.0.0.0/0 with the default port:**

```bash
# cloud security group ingress: any source, management port open
aws ec2 authorize-security-group-ingress --group-id sg-0a1b2c3d \
  --protocol tcp --port 8443 --cidr 0.0.0.0/0
```

**Hardened configuration — management plane restricted to a bastion prefix and a non-default port:**

```bash
aws ec2 revoke-security-group-ingress --group-id sg-0a1b2c3d \
  --protocol tcp --port 8443 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id sg-0a1b2c3d \
  --protocol tcp --port 8443 --cidr 203.0.113.0/28   # bastion egress range
# re-scan: the port now answers only from the bastion prefix
```

**Why this matters:** external exposure is decided by the ingress rule and its source prefix, so the security-group change is the remediated control and the second scan is the verification, not a courtesy.

## When It Is NOT This Issue

- **Honeypot or sinkhole range.** Some providers route unused addresses to a responder that accepts every port; the giveaway is identical banners and identical latency across unrelated IPs.
- **Anycast or CDN edge.** A port open on every address in a /24 is usually one edge fleet, not 256 hosts; resolve the address to an ASN before reporting a host count.
- **Scan-block page mistaken for a service.** A 403 with a vendor block string is the WAF answering, so the origin service behind it is unproven.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `network-recon-and-port-scanning-external-perimeter-scanning` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `network-recon-and-port-scanning-external-perimeter-scanning` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: network-recon-and-port-scanning-external-perimeter-scanning
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: T1046]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-recon-and-port-scanning-internal-network-mapping`](../network-recon-and-port-scanning-internal-network-mapping/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`firewall-and-segmentation-testing`](../firewall-and-segmentation-testing/SKILL.md) - Network, Active Directory and Endpoint (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `network-recon-and-port-scanning-external-perimeter-scanning` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1046`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 10 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/github_security_md (3), CYBER_CPT/blackhills (2), OffsecCyber (1), CYBER_CPT/nuclei_templates (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 3 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
