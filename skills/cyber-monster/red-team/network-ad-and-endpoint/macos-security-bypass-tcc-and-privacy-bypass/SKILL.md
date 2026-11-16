---
name: macos-security-bypass-tcc-and-privacy-bypass
description: macOS TCC and privacy control bypass. Covers TCC database manipulation, prompt abuse and entitlement paths to reach protected user data. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["tcc bypass", "macos privacy bypass", "tcc.db", "full disk access"]
cwe: [CWE-269]
owasp: []
attack: [T1548]
capec: [CAPEC-233]
related: [macos-security-bypass, macos-security-bypass-gatekeeper-and-notarization, network-recon-and-port-scanning, service-enumeration]
parent: macos-security-bypass
---

# Macos Security Bypass Tcc and Privacy Bypass - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

TCC is a per-service, per-client authorisation database: a process asks for a service such as full disk access or the microphone, and the system records a grant against the client's code identity. The bypass classes follow from that design — a process can inherit another process's grant by having code injected into it, a helper can hold a grant the parent does not, a signed installer can be tricked into performing the access, or the database can be edited directly with full disk access. Since macOS 26 the prompting client must be Developer ID signed with the hardened runtime, which removed the ad-hoc binary path.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`macos-security-bypass`](../macos-security-bypass/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the objective is protected user data **THEN** full disk access is the highest-value service; check which clients hold it
3. **IF** a signed application performs the access **THEN** the grant belongs to the signed identity, so check the helper and the entitlements
4. **IF** the binary is ad-hoc signed **THEN** it cannot prompt on macOS 26 and later; the finding is the OS version and the signature state together
5. **IF** the TCC database is writable **THEN** that requires full disk access already, so it is a consequence rather than a path
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `macos-security-bypass-tcc-and-privacy-bypass` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Gatekeeper and notarization | [`macos-security-bypass-gatekeeper-and-notarization`](../macos-security-bypass-gatekeeper-and-notarization/SKILL.md) | Delivery and assessment |
| Overall layer state | [`macos-security-bypass`](../macos-security-bypass/SKILL.md) | SIP and global settings |
| Persistence to re-establish access | [`host-persistence-linux-and-macos-persistence`](../host-persistence-linux-and-macos-persistence/SKILL.md) | launchd mechanisms |
| Delivery to the user | [`initial-access-via-phishing`](../initial-access-via-phishing/SKILL.md) | How the binary arrives |
| Need the class-level branch table first | [`macos-security-bypass`](../macos-security-bypass/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate the services and their clients.** The TCC database lists service, client and grant value. Reading it requires full disk access, so an unprivileged read is itself evidence about the current context; use `tccutil` and the privacy preference panes for a supported view.
2. **Read the client's code identity.** TCC records the client by bundle identifier and code requirement. A binary whose signature does not satisfy the recorded requirement cannot reuse the grant, which is why the signature state matters as much as the grant.
3. **Establish the OS-version behaviour.** macOS 26 requires Developer ID signing with the hardened runtime to prompt. An ad-hoc binary on macOS 26 therefore cannot obtain a new grant, which changes the finding from 'bypass possible' to 'capability bounded'.
4. **Name the stop condition and the safety rule.** Stop at the first grant whose client identity is unexpected or whose access exceeds its purpose. Editing the TCC database requires full disk access and disables SIP, so it is a high-impact change that needs explicit authorisation.
5. **State the proof.** Proof is the service, the client identity, the grant value and the code-signing state of that client. A file being readable is not proof of a TCC bypass without the grant record.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `kTCCServiceSystemPolicyAllFiles` grant | Proves full disk access for that client, which reaches every protected path; macOS with TCC. |
| TCC client recorded by bundle id with a code requirement | Proves the grant is bound to a signature, so a different binary cannot reuse it; macOS. |
| Ad-hoc signed binary requesting a service on macOS 26 | Proves the prompt cannot be triggered, which bounds the technique; macOS 26 and later. |
| Helper process holding a grant the parent does not | Proves an indirection path where the parent asks the helper to perform the access; macOS with app helpers. |
| `tccd` log entry denying a request | Proves the control refused the access, which is the detection signal; macOS. |

## Worked Contrast

**Weak configuration — full disk access granted to a broad utility and a terminal application:**

```bash
# TCC grants full disk access to a terminal emulator and a file manager,
# so any script run from that terminal inherits the grant
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "select service,client,auth_value from access where service like '%AllFiles%'"
# every process spawned from that terminal reads protected paths
```

**Hardened configuration — full disk access limited to the specific signed tools that need it:**

```bash
sudo tccutil reset SystemPolicyAllFiles <bundle-id>
# then grant only the specific signed helper that performs the operation
# verification: the access table shows the narrow client and the terminal no longer appears
```

**Why this matters:** a grant is inherited by anything running inside the granted client, so the control is the grant scope and the verification is the access table rather than a file-read attempt.

## When It Is NOT This Issue

- **A user-granted permission after a prompt.** That is the design; the finding is a grant without a prompt, or one inherited by unrelated code.
- **A grant for a signed vendor app that performs backups.** Backup tools legitimately need full disk access; check the signature and the vendor.
- **A TCC read failure.** Reading the database without full disk access fails by design; that is not evidence of tampering.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `macos-security-bypass-tcc-and-privacy-bypass` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `macos-security-bypass-tcc-and-privacy-bypass` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: macos-security-bypass-tcc-and-privacy-bypass
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1548]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`macos-security-bypass`](../macos-security-bypass/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`macos-security-bypass-gatekeeper-and-notarization`](../macos-security-bypass-gatekeeper-and-notarization/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`network-protocol-attacks`](../network-protocol-attacks/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `macos-security-bypass-tcc-and-privacy-bypass` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1548`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/go_exploitdb (3), CYBER_CPT/pentest_partners (2), CYBER_CPT/expku (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
