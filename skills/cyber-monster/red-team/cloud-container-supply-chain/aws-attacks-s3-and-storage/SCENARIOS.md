# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`aws-attacks-s3-and-storage`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: GCP - Public Buckets Privilege Escalation

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud`
- **Context / Surface:** Cloud Security Guide (en)
- **Root Cause / Analysis:** GCP - Public Buckets Privilege Escalation Buckets Privilege Escalation If the bucket policy allowed either “allUsers” or “allAuthenticatedUsers” to **write to their bucket policy** (the **storage.buckets.setIamPolicy** permission)**,** then anyone can modify the bucket policy and grant himself full...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: HTB: Rebound

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Rebound is a monster Active Directory / Kerberos box. I’ll start off with a RID-cycle attack to get a list of users, and combine AS-REP-Roasting with Kerberoasting to get an crackable hash for a service account. That password is shared by a domain user, and I’ll find a bad ACL th
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: ACE 滥用完整利用链参考

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** # ACE 滥用完整利用链参考 Active Directory 中的访问控制项 (ACE) 定义了谁对哪个对象拥有什么权限。错误配置的 ACE 可以被用于权限提升、凭据窃取和持久化。 ## 1. ACE 类型与权限掩码 ### 关键权限及其十六进制值 / 权限名称 / 十六进制值 / 含义 / /----------/------------/------/ / GenericAll / '0x10000000' / 完全控制（读/写/删除/修改权限） / / GenericWrite / '0x40000000' / 写入所有可写属性 / / Wri
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: Haze

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Haze is built around an instance of Splunk Enterprise. I’ll start by exploiting a directory traversal / file read in Splunk that allows me to leak configuration files that container encrypted passwords. I’ll exfil the key and decrypt them, finding a password that’s reused by a us
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: AWS s3 Bucket Versioning Discloses Secrets

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-269`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # AWS s3 Bucket Versioning Discloses Secrets > Intro : _Hello Hackers!!👋 What's up. Hope you all are Fine. Today I am discussing about AWS S3 Bucket Versioning and with that how Hackers can perform Malicious Task like Access AWS Creds or Information Disclosure. Though it is a Lab
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Shadow Credentials 与 RBCD 组合攻击

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** # Shadow Credentials 与 RBCD 组合攻击 > 当 BloodHound 显示你对目标对象有 GenericWrite/GenericAll 权限时，Shadow Credentials 和 RBCD 是两条最隐蔽的提权路径。两者可以独立使用，也可以组合形成链式攻击。 --- ## 1. Shadow Credentials 攻击详解 ### 1.1 原理 'text Shadow Credentials 利用 Windows Hello for Business 的 Key Trust 机制： ├─ msDS-KeyCrede
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Abusing Active Directory ACLs/ACEs

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-269`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # Abusing Active Directory ACLs/ACEs ## Overview Delegated Managed Service Accounts (**dMSAs**) are a brand‑new AD principal type introduced with **Windows Server 2025**. They are designed to replace legacy service accounts by allowing a one‑click “migration” that automatically c
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
