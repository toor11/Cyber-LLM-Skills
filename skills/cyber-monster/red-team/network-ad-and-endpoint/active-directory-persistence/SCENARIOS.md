# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`active-directory-persistence`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: SID-History Injection

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** SID-History Injection SID History Injection Attack The focus of the **SID History Injection Attack** is aiding **user migration between domains** while ensuring continued access to resources from the former domain.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: T1098.003 - Account Manipulation: Additional Cloud Roles

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-269`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1098.003 - Account Manipulation: Additional Cloud Roles ## Description from ATT&CK An adversary may add additional roles or permissions to an adversary-controlled cloud account to maintain persistent access to a tenant. > **Jargon: Tenant** — A dedicated and secure instance of
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: T1136.003 - Create Account: Cloud Account

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-269`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1136.003 - Create Account: Cloud Account ## Description from ATT&CK Adversaries may create a cloud account to maintain access to victim systems. With a sufficient level of access, such accounts may be used to establish secondary credentialed access that does not require persis
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Backdooring AdminSDHolder for Persistence

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Backdooring AdminSDHolder for Persistence ## AdminSDHolder 'AdminSDHolder' is a special AD container with some "default" security permissions that is used as a template for protected AD accounts and groups (like Domain Admins, Enterprise Admins, etc.) to prevent their accidenta
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: DCShadow - Becoming a Rogue Domain Controller

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # DCShadow - Becoming a Rogue Domain Controller DCShadow allows an attacker with enough privileges to create a rogue Domain Controller and push changes to the DC Active Directory objects. ## Execution For this lab, two shells are required - one running with 'SYSTEM' privileges an
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: T1098-Windows-AdminSDHolder

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** # T1098-Windows-AdminSDHolder ## 来自ATT&CK的描述 帐户操作可以帮助攻击者维持在环境中对凭据和某些权限级别的访问。账户操作可能包括修改权限，修改凭据，添加或更改权限组，修改帐户设置或修改执行身份验证等方式。为了创建或操纵帐户，攻击者必须已经对系统或域具有足够的权限。 ## 测试案例 AdminSDHolder是一个特殊的AD容器，具有一些默认安全权限，用作受保护的AD账户和组的模板。 Active Directory将采用AdminSDHolder对象的ACL并定期将其应用于所有受保护的AD账户和组，以防止意外和无意
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: AdminSDHolder

- **Provenance:** Source: `CYBER_CPT/hacker_recipes` | CWE: `CWE-269`
- **Context / Surface:** Source: hacker_recipes (en)
- **Root Cause / Analysis:** # AdminSDHolder ## Theory AdminSdHolder protects domain objects against permission changes. "AdminSdHolder" either refers to a domain object, a "worker code" or an operation depending on the context. The operation consists in the PDC (Principal Domain Controller) Emulator restori
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
