---
name: initial-access-via-phishing
description: "Achieves initial access through phishing: pretext design, payload and link delivery, device code and MFA fatigue flows, macro and container abuse, and click-tracking discipline. Use when an engagement permits social engineering."
family: network-ad-and-endpoint
tier: core
triggers: ["phishing", "initial access phishing", "payload delivery email", "mfa fatigue", "device code phishing"]
cwe: [CWE-284]
owasp: []
attack: [T1566]
capec: [CAPEC-163]
related: [network-recon-and-port-scanning, service-enumeration, network-protocol-attacks, firewall-and-segmentation-testing]
---

# Initial Access via Phishing - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **core** | Paired Counterpart: [`email-security-monitoring`](../../../blue-team/detection-and-monitoring/email-security-monitoring/SKILL.md)

## Mechanism and Preconditions

Phishing succeeds when the message, the delivery mechanism and the user's available action line up: a link that leads to a credential page, an attachment that a document reader opens, or an instruction that persuades the user to run a command themselves. Since 2025 the instruction-based variant has dominated — a fake verification page asks the user to paste a command into the Windows Run dialog or a terminal — because it produces execution with no attachment and no exploit. The finding is which of those three channels was available and what control would have intercepted it.

- **CWE-284 (Improper Access Control):** The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the message is a credential page rather than an attachment **THEN** the control is MFA method strength and conditional access, not mail filtering
2. **IF** the message asks the user to paste a command **THEN** that is the fake-captcha pattern; the detection surface is `RunMRU` and the child process, not the mail body
3. **IF** the attachment is a document that needs a reader **THEN** mark-of-the-web and macro policy decide whether it can execute; check both before assessing the payload
4. **IF** the delivery is a messaging platform rather than mail **THEN** mail gateway controls do not apply; the control is endpoint execution policy and user reporting
5. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`email-security-monitoring`](../../../blue-team/detection-and-monitoring/email-security-monitoring/SKILL.md) and keep this file for attack-path evidence only
6. **IF** required preconditions for `initial-access-via-phishing` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The lure leads to an internet-facing appliance | [`initial-access-via-edge-devices`](../initial-access-via-edge-devices/SKILL.md) | No user interaction required |
| The user is persuaded to run a signed binary | [`lolbins-and-signed-binary-abuse-execution-proxies`](../lolbins-and-signed-binary-abuse-execution-proxies/SKILL.md) | Execution proxy selection |
| The delivery needs a payload host | [`lolbins-and-signed-binary-abuse-download-and-staging`](../lolbins-and-signed-binary-abuse-download-and-staging/SKILL.md) | Download and staging semantics |
| The credential is captured and reused | [`entra-id-and-hybrid-identity`](../entra-id-and-hybrid-identity/SKILL.md) | Token and identity abuse after capture |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Identify the channel the message actually opens.** A link, an attachment, a phone number, or an instruction. Each has a different control: mail filtering and URL rewriting for links, attachment policy and MOTW for files, endpoint execution policy for instructions. Assessing the wrong control produces a finding that cannot be remediated.
2. **Read the authentication context of the message.** SPF, DKIM and DMARC results, the sending infrastructure, and the reply-to. A message that passes authentication from a lookalike domain is a different problem from one that fails and was delivered anyway.
3. **Establish the user-action differential.** Replay the lure in a controlled browser and endpoint and record what the user would see and what executing the instruction would produce. The differential is the gap between the visible page and the actual effect, which is what the training and the control must address.
4. **Name the stop condition and the authorisation boundary.** Phishing simulation requires explicit authorisation per target group and a documented escalation path for a user who reports it. Stop immediately if a real credential is entered or a real user reports the message as suspicious.
5. **State the proof.** Proof is the message's authentication result, the URL or attachment hash, the user action required, and the control that did or did not intercept it. A screenshot of the landing page is supporting material, not proof of impact.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| DMARC `p=none` on the impersonated domain | Proves the domain owner cannot enforce rejection, so spoofed mail reaches recipients; any mail domain. |
| Executable or script attachment with MOTW absent | Proves the download did not receive the zone identifier, which disables Protected View and macro blocking; Windows with a proxy that strips the header. |
| Fake verification page instructing a Run-dialog paste | Proves an instruction-based lure that needs no attachment, detected through `RunMRU` rather than the mail body; Windows. |
| `RunMRU` value containing `mshta`, `powershell` or a URL | Proves the user pasted and executed a command, which is the post-delivery evidence; Windows. |
| Lookalike domain registered within 30 days | Proves infrastructure built for the campaign, which is actionable for blocking before delivery; any mail flow. |

## Worked Contrast

**Weak configuration — mail accepted with a failing DMARC policy and attachments delivered without MOTW:**

```powershell
# receiving domain: no DMARC enforcement, and the gateway delivers
# attachments whose zone identifier was stripped in transit
Get-TransportRule | Where-Object { $_.Name -match 'DMARC' }
# no rule quarantines a DMARC fail, and Protected View never engages
```

**Hardened configuration — DMARC enforced at the gateway and MOTW preserved end to end:**

```powershell
New-TransportRule -Name 'Quarantine DMARC Fail' -FromScope NotInOrganization `
    -DmarcPolicyReject $false -DmarcPolicyQuarantine $true -Quarantine $true
# and: do not strip Content-Type or X-Ms-Exchange-Organization headers in the proxy
# verification: a test message from a failing domain is quarantined and an attachment carries Zone.Identifier
```

**Why this matters:** delivery and execution are separate controls, so the finding must name which one failed; the verification is a quarantined test message plus an attachment that still carries its zone identifier.

## When It Is NOT This Issue

- **A legitimate bulk sender failing DMARC because of forwarding.** Mailing lists break SPF alignment by design; check the ARC chain before treating the failure as spoofing.
- **A user reporting a simulation.** Reports during an authorised simulation are a success metric, not an incident; confirm the campaign calendar before escalating.
- **A URL that resolves to a sanctioned SaaS tenant.** Lookalike names often point at real tenants; resolve the destination before calling it malicious infrastructure.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `initial-access-via-phishing` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `initial-access-via-phishing` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: initial-access-via-phishing
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: T1566]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`email-security-monitoring`](../../../blue-team/detection-and-monitoring/email-security-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`firewall-and-segmentation-testing`](../firewall-and-segmentation-testing/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-enumeration`](../active-directory-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `initial-access-via-phishing` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, T1566`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 11 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/blackhills (5), CYBER_CPT/atomic_red_team (2), CYBER_CPT/github_security_md (2), bugbounty-hunter-v1 (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 4 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
