---
name: ssrf-cloud-metadata
description: SSRF against cloud instance metadata services. Covers AWS IMDSv1 and IMDSv2 flow, GCP metadata with required header, Azure IMDS, and provider-specific credential and identity token paths. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["ssrf metadata", "169.254.169.254", "imds", "instance metadata ssrf", "cloud metadata"]
cwe: [CWE-918]
owasp: [A10:2021]
attack: [T1190]
capec: [CAPEC-664]
related: [ssrf, ssrf-internal-service-pivot, ssrf-protocol-smuggling, ssrf-allowlist-bypass]
parent: ssrf
---

# SSRF Cloud Metadata - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)

## Mechanism and Preconditions

A cloud metadata SSRF forces the server to fetch its instance metadata endpoint at the link-local address 169.254.169.254, where the instance role credentials and identity tokens live. Each provider gates access differently: AWS IMDSv2 requires a PUT to obtain a token and the `X-aws-ec2-metadata-token` header on every read, GCP requires the `Metadata-Flavor: Google` header on `computeMetadata/v1`, and Azure requires `Metadata: true` with an api-version. The security decision is whether the fetch client can both reach the link-local address and carry the provider-required method and headers; a plain GET with no custom header cannot complete IMDSv2, but a request forgery that also injects headers can. The attacker gains the role temporary credentials from `iam/security-credentials`, so this variant impact is credential exposure rather than mere internal reachability.

- **Precondition chain:** A request-controlled fetch can reach 169.254.169.254, the client can issue the provider-required method and headers or the instance still allows IMDSv1, and the metadata response is observable or its credentials are usable.
- **Readable differential:** A fetch to the metadata base path with the required header versus without it; a finding exists when the header-bearing request returns role data while the plain request is refused, and it closes when the fetch tier cannot reach link-local or cannot set metadata headers.
- **Empirical grounding:** CWE-918 under OWASP Top 10:2025 A01:2025 Broken Access Control; CVE-2025-64709 (Typebot webhook SSRF, GHSA-8gq9-rw7v-3jpr, fixed 3.13.1) is a 2025 IMDSv2 bypass where custom header injection let the forged request satisfy the token-header requirement.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed to target instance metadata **THEN** start at the parent class [`ssrf`](../ssrf/SKILL.md) first (1 hop)
2. **IF** the metadata address is unreachable from the fetch tier **THEN** classify as a non-finding; record the egress restriction as the compensating control
3. **IF** the instance enforces IMDSv2 and the client sends only GET **THEN** check whether header injection can supply the token header before claiming impact
4. **IF** the provider is GCP **THEN** require the Metadata-Flavor: Google header on computeMetadata/v1
5. **IF** the provider is Azure **THEN** require Metadata: true and an api-version on the IMDS path
6. **IF** the fetch follows redirects **THEN** test an allowed host that 302s to 169.254.169.254, overlapping [`ssrf-allowlist-bypass`](../ssrf-allowlist-bypass/SKILL.md)
7. **IF** no response body is returned **THEN** switch to [`ssrf-blind-ssrf`](../ssrf-blind-ssrf/SKILL.md) (1 hop) for out-of-band confirmation
8. **IF** the goal is an internal service rather than metadata **THEN** switch to [`ssrf-internal-service-pivot`](../ssrf-internal-service-pivot/SKILL.md) (1 hop)
9. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)
10. **IF** link-local is unreachable and no header can be set **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Allowed host redirects to link-local | [`ssrf-allowlist-bypass`](../ssrf-allowlist-bypass/SKILL.md) | The reach is a redirect parser gap, a different invariant |
| No body returned from the metadata fetch | [`ssrf-blind-ssrf`](../ssrf-blind-ssrf/SKILL.md) | Confirmation moves to out-of-band or timing |
| Reaches an internal service, not metadata | [`ssrf-internal-service-pivot`](../ssrf-internal-service-pivot/SKILL.md) | Impact is service interaction, not credential theft |
| Need parent class methodology | [`ssrf`](../ssrf/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the fetch tier can address link-local.** Establish whether 169.254.169.254 is reachable from the component issuing the request; if egress to link-local is blocked, the metadata path is closed regardless of the parser.
2. **Identify the cloud provider and its metadata contract.** AWS IMDSv2 needs a PUT token and `X-aws-ec2-metadata-token`, GCP needs `Metadata-Flavor: Google`, and Azure needs `Metadata: true` and an api-version. The branch is chosen by provider fingerprint, not by trial.
3. **Test whether the client can satisfy the contract.** Determine if the forgery can set the required header or method; a plain GET with no custom header cannot complete IMDSv2, while a header-injection primitive, as in the 2025 Typebot case, can.
4. **Baseline a benign metadata path.** Request a non-sensitive key such as the instance id or a region field to confirm reachability and header handling before touching credential paths.
5. **Probe the credential path read-only.** Reach `iam/security-credentials` or the identity token path only far enough to confirm a role name is listed; enumerating the role proves exposure without exfiltrating the secret material.
6. **Stop condition.** Halt when the fetch returns role or token data through the required header, or is refused for every provider-correct header and method, or would require using the returned credentials. The first confirms, the second is a non-finding, the third is out of scope.
7. **State what counts as proof.** Proof is a metadata response containing a role name or token field, retrieved by a server-issued request carrying the provider-required header, plus the code line that let the destination and headers be request-controlled. Reaching 169.254.169.254 without the required header, or without a readable response, is not proof of credential exposure.
8. **Close with the structural fix.** Enforce IMDSv2 with a hop limit, block the fetch tier from link-local egress, resolve-and-pin destinations to a public allowlist, and strip request-controlled headers from the outbound call. Verify by replaying the header-bearing metadata probe against the patched build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A fetch reaching 169.254.169.254 from the application host | Proves link-local reachability on AWS, GCP, or Azure, with impact then depending on the header contract |
| `X-aws-ec2-metadata-token` obtainable or injectable by the forged request | Proves the client can complete IMDSv2, the gate that distinguishes reachable from exploitable on AWS |
| `Metadata-Flavor: Google` accepted on computeMetadata/v1 | Proves the GCP header contract is satisfied by the forged request |
| `Metadata: true` with an api-version returning Azure IMDS data | Proves the Azure metadata contract is met through the fetch |
| A role name listed under iam/security-credentials | Proves credential-exposure scope without exfiltrating the secret, on AWS instance roles |
| A plain GET to metadata refused while a header-bearing GET succeeds | Proves IMDSv2 is enforced and that header control is the deciding factor |
| A custom header injected into the outbound fetch | Proves the bypass class behind the 2025 Typebot webhook SSRF, which defeated the IMDSv2 guard |

## Worked Contrast

**Vulnerable pattern:**

```python
import requests

def run_webhook(url: str, extra_headers: dict) -> bytes:
    # Caller-supplied headers are forwarded verbatim, so a token header can be injected,
    # and the destination is unrestricted, so 169.254.169.254 is reachable
    return requests.get(url, headers=extra_headers, timeout=5).content
```

**Hardened pattern:**

```python
import ipaddress
import socket
import urllib.parse
import requests

ALLOWED = {"hooks.partner.example"}

def run_webhook(url: str, extra_headers: dict) -> bytes:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED:
        raise ValueError("destination not allowed")
    addr = socket.getaddrinfo(parts.hostname, 443, proto=socket.IPPROTO_TCP)[0][4][0]
    if not ipaddress.ip_address(addr).is_global:
        raise ValueError("resolves to a non-public address")
    # Drop caller headers entirely so no metadata token header can be injected
    return requests.get(url, timeout=5, allow_redirects=False).content
```

**Why this matters:** The defect forwards caller-controlled headers to an unrestricted destination, exactly the primitive that completed the IMDSv2 token flow in the 2025 webhook SSRF. The fix pins to a public allowlist, rejects link-local answers, forbids redirects, and discards caller headers, so neither the address nor the required metadata header can be supplied by the attacker.

## When It Is NOT This Issue

- **Link-local blocked at egress:** reaching the parser does not help if the fetch tier cannot route to 169.254.169.254.
- **IMDSv2 enforced, no header control:** a plain GET that cannot set the token header returns nothing useful, so reachability alone is not credential exposure.
- **Non-sensitive key only:** returning an instance id or availability zone is reachability evidence, not a credential finding.
- **Hop limit blocks proxied access:** an IMDSv2 hop limit of one stops a containerised proxy from reaching metadata even when the fetch exists.
- **Credentials present but constrained:** a token the environment restricts to deny-all is a defect at reduced severity.
- **Provider header missing:** a fetch without `Metadata-Flavor: Google` or `Metadata: true` is refused by design and is not a bypass.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ssrf-cloud-metadata` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ssrf-cloud-metadata` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ssrf-cloud-metadata
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-918 | Mapping: T1190]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md) - Blue Detection/Defense Counterpart
- [`ssrf`](../ssrf/SKILL.md) - Web and Application (flagship)
- [`ssrf-internal-service-pivot`](../ssrf-internal-service-pivot/SKILL.md) - Web and Application (leaf)
- [`ssrf-protocol-smuggling`](../ssrf-protocol-smuggling/SKILL.md) - Web and Application (leaf)
- [`ssrf-allowlist-bypass`](../ssrf-allowlist-bypass/SKILL.md) - Web and Application (leaf)
- [`ssrf-blind-ssrf`](../ssrf-blind-ssrf/SKILL.md) - Web and Application (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ssrf-cloud-metadata` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-918, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 27 |
| Distinct dataset sources | 7 |
| Top sources | OffsecCyber (15), CYBER_CPT/gh_advisories (3), CYBER_CPT/osv (3), cyber-security/security-code (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
