---
name: active-directory-kerberos-attacks-ticket-abuse-and-forgery
description: Kerberos ticket manipulation. Covers ticket dumping, pass-the-ticket, overpass-the-hash and ticket renewal abuse to move between hosts using Kerberos material only. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["pass the ticket", "overpass the hash", "ticket dump", "kirbi"]
cwe: [CWE-269]
owasp: []
attack: [T1558]
capec: [CAPEC-509]
related: [active-directory-kerberos-attacks, active-directory-kerberos-attacks-kerberoasting, active-directory-kerberos-attacks-asrep-roasting, active-directory-kerberos-attacks-golden-and-silver-tickets]
parent: active-directory-kerberos-attacks
---

# Active Directory Kerberos Attacks Ticket Abuse and Forgery - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`hardening-windows-and-ad-authentication-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-authentication-hardening/SKILL.md)

## Mechanism and Preconditions

A Kerberos ticket in a cache is a bearer credential: presenting it satisfies authentication without any password being sent. Overpass-the-hash is the bridge case, where an NTLM hash is used to request a TGT, after which every subsequent authentication is Kerberos and looks normal. Because the ticket is a file or an LSASS structure rather than a network exchange, the artefact is the ticket cache itself — its encryption type, its flags, and the mismatch between the account's logon history and the services it can suddenly reach.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`active-directory-kerberos-attacks`](../active-directory-kerberos-attacks/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** only an NTLM hash is held, no ticket **THEN** overpass-the-hash: request a TGT with the hash, which converts a hash into a Kerberos-visible logon
3. **IF** a ticket file is held **THEN** inject it and observe whether the service accepts it; the finding is acceptance, not possession
4. **IF** a plaintext password is held **THEN** requesting a TGT normally is not ticket abuse; that is ordinary authentication and should be described as such
5. **IF** the ticket has to survive a reboot **THEN** that is persistence, not abuse; see [`active-directory-persistence`](../active-directory-persistence/SKILL.md)
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`hardening-windows-and-ad-authentication-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-authentication-hardening/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `active-directory-kerberos-attacks-ticket-abuse-and-forgery` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Forged rather than captured tickets | [`active-directory-kerberos-attacks-golden-and-silver-tickets`](../active-directory-kerberos-attacks-golden-and-silver-tickets/SKILL.md) | Requires key material |
| Delegation produces the ticket | [`active-directory-kerberos-attacks-delegation`](../active-directory-kerberos-attacks-delegation/SKILL.md) | S4U chains |
| The hash comes from a host dump | [`credential-dumping-dpapi-and-secret-stores`](../credential-dumping-dpapi-and-secret-stores/SKILL.md) | Where hashes are recovered |
| The ticket must be made durable | [`active-directory-persistence`](../active-directory-persistence/SKILL.md) | Persistence mechanisms |
| Need the class-level branch table first | [`active-directory-kerberos-attacks`](../active-directory-kerberos-attacks/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm what is actually held.** A TGT cache, a service ticket, an NTLM hash, or an AES key. Each maps to a different branch: injection, overpass-the-hash, or forgery. Reporting a hash as a ticket misstates the technique and the detection.
2. **Read the ticket's own metadata before using it.** `klist -e -f` gives the encryption type and flags; a TGT with `forwardable` and `renewable` behaves differently from one without. The ticket's flags decide what delegation and renewal are possible.
3. **Baseline the account's normal authentication pattern.** Note the account's usual source hosts and logon types. The differential is a Kerberos logon from a host where that account has never authenticated, which is what makes ticket injection visible at all.
4. **Set the stop condition at the first accepted request.** One successful service access proves the ticket is valid for that service. Repeated access creates a usage trail without adding evidence.
5. **State the proof.** Proof is a service accepting the ticket, evidenced by the service's 4624 with `Authentication Package: Kerberos` and a `Logon GUID` that has no matching 4768 or 4769 on the DC for that principal. For overpass-the-hash, a 4768 issued with the account's hash-derived key followed by 4624 logon type 9 on the target host.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Logon type 9 in 4624 | Proves a `NewCredentials` logon, the shape Mimikatz's overpass-the-hash produces; Windows hosts. |
| `klist -e -f` ticket flags | Proves what the held ticket can do (forwardable, renewable, proxy) before any use; Windows client. |
| 4768 with `PreAuthType` 2 and no prior 4768 | Proves a TGT was obtained with a key rather than an interactive logon; domain controllers. |
| Service 4624 with no DC 4769 | Proves a ticket was replayed rather than issued in that session; service hosts compared with DC logs. |
| `KRB5CCNAME` cache file on Linux | Proves a ccache exists outside the normal keytab flow, which is the Linux-side artefact of the same technique; Linux hosts. |

## Worked Contrast

**Weak configuration — long ticket lifetime and no privileged access workstation boundary:**

```powershell
# domain policy: 10-hour tickets, 7-day renewal, no restriction on where Tier-0 logs on
$d = Get-ADDomain
$d.MaxTicketAge
$d.MaxRenewAge
# a captured TGT from a workstation is reusable for the full renewal window
```

**Hardened configuration — short ticket lifetime, renewal disabled for privileged accounts, and PAWs enforced:**

```powershell
Set-ADDefaultDomainPasswordPolicy -MaxTicketAge '04:00:00' -MaxRenewAge '1.00:00:00'
# plus: privileged accounts restricted to PAWs via authentication policy silos
New-ADAuthenticationPolicySilo -Name Tier0Silo -Enforce
# verification: a captured TGT expires in four hours and cannot be renewed
```

**Why this matters:** a bearer ticket's value is its remaining lifetime and its reachability, so shortening the lifetime and confining where privileged accounts can authenticate is the control that limits replay.

## When It Is NOT This Issue

- **A ticket exported for legitimate automation.** Service accounts using keytabs or managed identities produce Kerberos logons without interactive history; check whether the host is a sanctioned automation platform.
- **`NewCredentials` logons from `runas /netonly`.** Administrators use logon type 9 routinely for cross-domain tooling; confirm the source host and the account's role before treating it as overpass-the-hash.
- **Clock skew producing invalid tickets.** A ticket rejected for time skew is not evidence of forgery; check the KDC's time service before drawing conclusions.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `active-directory-kerberos-attacks-ticket-abuse-and-forgery` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `active-directory-kerberos-attacks-ticket-abuse-and-forgery` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: active-directory-kerberos-attacks-ticket-abuse-and-forgery
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1558]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`hardening-windows-and-ad-authentication-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-authentication-hardening/SKILL.md) - Blue Detection/Defense Counterpart
- [`active-directory-kerberos-attacks`](../active-directory-kerberos-attacks/SKILL.md) - Network, Active Directory and Endpoint (flagship)
- [`active-directory-kerberos-attacks-kerberoasting`](../active-directory-kerberos-attacks-kerberoasting/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-kerberos-attacks-asrep-roasting`](../active-directory-kerberos-attacks-asrep-roasting/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-kerberos-attacks-golden-and-silver-tickets`](../active-directory-kerberos-attacks-golden-and-silver-tickets/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`active-directory-kerberos-attacks-delegation`](../active-directory-kerberos-attacks-delegation/SKILL.md) - Network, Active Directory and Endpoint (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `active-directory-kerberos-attacks-ticket-abuse-and-forgery` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1558`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 22 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/oxdf (9), CYBER_CPT/github_security_md (8), CYBER_CPT/sigmahq (1), CYBER_CPT/atomic_red_team (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
