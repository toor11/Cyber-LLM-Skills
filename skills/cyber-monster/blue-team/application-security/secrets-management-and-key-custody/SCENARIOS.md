# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`secrets-management-and-key-custody`](SKILL.md) | Family: **Application Security**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Cloud Secrets Management Stores

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Cloud Secrets Management Stores **ID**: T1555.006 **Type**: Technique **Tactics**: Credential Access **Platforms**: IaaS Adversaries may acquire credentials from cloud-native secret management solutions such as AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, and Terraform Vault.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: HTB: Vault

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-798`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Vault was a really neat box in that it required pivoting from a host into various VMs to get to the vault, at least the intended way. There’s an initial php upload filter bypass that gives me execution. Then a pivot with an OpenVPN config RCE. From there I’ll find SSH creds, and
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Proving Grounds Practice — Vault

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-798`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Proving Grounds Practice — Vault This is an easy box on Offsec’s PG Practice but the community disagrees and rates it as hard. There is a trick to this machine that I find super exciting — pure witchcraft. Start with a Nmap scan: 'bash sudo nmap -Pn -n $IP -sC -sV -p- --open
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Vault 101 : Samsung CTF Android Reverse Engineering Challenge Write-up

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-798`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Vault 101 : Samsung CTF App Reverse Engineering Challenge Write-up Write-up for Samsung SCTF’s Android Reverse Engineering Challenge : Vault 101 using pure static analysis based reverse engineering. # Background Challenge : Find the password. File given : Vault101–1.1-release.a
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Secrets Management Cheat Sheet

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-798`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Secrets Management Cheat Sheet ## 1 Introduction Secrets are being used everywhere nowadays, especially with the popularity of the DevOps movement. Application Programming Interface (API) keys, database credentials, Identity and Access Management (IAM) permissions, Secure Shell
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: Skyfall

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-798`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Skyfall is all about enumerating technolories like MinIO and Vault. I’ll start with a demo website that has a MinIO status page blocked by nginx. I’ll abuse a parser breakdown between nginx and flask to get access to the page, and learn the MinIO domain. From there, I’ll exploit
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: HTB: Authority

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-798`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Authority is a Windows domain controller. I’ll access open shares over SMB to find some Ansible playbooks. I’ll crack some encrypted fields to get credentials for a PWM instance. The PWM instance is in configuration mode, and I’ll use that to have it try to authenticate to my box
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
