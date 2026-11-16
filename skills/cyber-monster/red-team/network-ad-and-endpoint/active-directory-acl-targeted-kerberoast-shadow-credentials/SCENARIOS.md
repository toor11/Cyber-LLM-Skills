# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`active-directory-acl-targeted-kerberoast-shadow-credentials`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Shadow Credentials

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Shadow Credentials Intro **Check the original post for all the information about this technique.** As **summary**: if you can write to the **msDS-KeyCredentialLink** property of a user/computer, you can retrieve the **NT hash of that object**.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: HTB: Outdated

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Outdated has three steps that are all really interesting. First, I’ll exploit Folina by sending a link to an email address collected via recon over SMB. Then I’ll exploit shadow credentials to move laterally to the next user. Finally, I’ll exploit the Windows Server Update Servic
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Attack Tactics 9: Shadow Creds for PrivEsc w/ Kent & Jordan

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-269`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # Attack Tactics 9: Shadow Creds for PrivEsc w/ Kent & Jordan > **Jargon: PrivEsc (Privilege Escalation)** — The act of exploiting a bug, design flaw, or configuration oversight in an operating system or application to gain elevated access to resources that are normally protected
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Shadow Credentials 与 RBCD 组合攻击

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** # Shadow Credentials 与 RBCD 组合攻击 > 当 BloodHound 显示你对目标对象有 GenericWrite/GenericAll 权限时，Shadow Credentials 和 RBCD 是两条最隐蔽的提权路径。两者可以独立使用，也可以组合形成链式攻击。 --- ## 1. Shadow Credentials 攻击详解 ### 1.1 原理 'text Shadow Credentials 利用 Windows Hello for Business 的 Key Trust 机制： ├─ msDS-KeyCrede
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Shadow Credentials

- **Provenance:** Source: `CYBER_CPT/hacker_recipes` | CWE: `CWE-269`
- **Context / Surface:** Source: hacker_recipes (en)
- **Root Cause / Analysis:** # Shadow Credentials ## Theory The Kerberos authentication protocol works with tickets in order to grant access. An ST (Service Ticket) can be obtained by presenting a TGT (Ticket Granting Ticket). That prior TGT can only be obtained by validating a first step named "pre-authenti
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Shadow Credentials

- **Provenance:** Source: `CYBER_CPT/ired_team` | CWE: `CWE-269`
- **Context / Surface:** Source: ired_team (en)
- **Root Cause / Analysis:** # Shadow Credentials This is a quick lab to familiarize with a technique called [Shadow Credentials] (https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) written about by [Elad Shamir] (https://medium.com/@elad.shamir?source=p
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Password - Shadow Credentials

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Password - Shadow Credentials > Add **Key Credentials** to the attribute 'msDS-KeyCredentialLink' of the target user/computer object and then perform Kerberos authentication as that account using PKINIT to obtain a TGT for that user. When trying to pre-authenticate with PKINIT,
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
