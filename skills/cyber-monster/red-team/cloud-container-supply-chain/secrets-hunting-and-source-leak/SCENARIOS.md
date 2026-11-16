# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`secrets-hunting-and-source-leak`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Github Dorks & Leaks

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Github Dorks & Leaks Tools to find secrets in git repos and file system - https://github.com/dxa4481/truffleHog - https://github.com/gitleaks/gitleaks - https://github.com/praetorian-inc/noseyparker - https://github.com/GitGuardian/ggshield - https://github.com/JaimePolop/RExpository -...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Tryhackme: Pickle Rick

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Tryhackme: Pickle Rick Pickle Rick is a TryHackMe easy machine in which we have to enumerate a web service and use some leaked credentials to access it. Finally we will exploit a command execution to get a shell on the machine. As usual in TryHackMe, we must connect to the VPN or use the AttackBox.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 3: Auditing GitLab: Public Gitlab Projects on Internal Networks

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-798`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # Auditing GitLab: Public Gitlab Projects on Internal Networks A great place that can sometimes be overlooked on an internal penetration test are the secrets hidden in plain sight. That is, a place where no authentication is required in many circumstances throughout internal netw
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Rooting For Secrets with TruffleHog

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-798`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # Rooting For Secrets with TruffleHog The potential leaking of confidential information can pose a significant security risk for any organization. When sensitive details (i.e., API keys The command below takes our TruffleHog JSON output—which can be massive and overwhelming—and c
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: AWS STS GetCallerIdentity Enumeration Via TruffleHog

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-798`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # AWS STS GetCallerIdentity Enumeration Via TruffleHog - **Level**: N/A - **Status**: experimental - **Author**: Adan Alvarez @adanalvarez - **Date**: 2025-10-12 - **Category**: Cloud ## Rule 'yaml title: AWS STS GetCallerIdentity Enumeration Via TruffleHog id: 9b1b8e9b-0a5d-4a
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: PUA - TruffleHog Execution

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-798`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # PUA - TruffleHog Execution / - **Level**: N/A - **Status**: experimental - **Author**: Swachchhanda Shrawan Poudel (Nextron Systems) - **Date**: 2025-09-24 - **Category**: Windows ## Rule 'yaml title: PUA - TruffleHog Execution id: 44030449-b0df-4c94-aae1-502359ab28ee related
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: PUA - AWS TruffleHog Execution

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-798`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # PUA - AWS TruffleHog Execution / - **Level**: N/A - **Status**: experimental - **Author**: Swachchhanda Shrawan Poudel (Nextron Systems) - **Date**: 2025-10-21 - **Category**: Cloud ## Rule 'yaml title: PUA - AWS TruffleHog Execution id: a840e606-7c8c-4684-9bc1-eb6b6155127f s
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: Gitleaks

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-798`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** ### Source https://github.com/gitleaks/gitleaks ### Scan entire history ' gitleaks detect --source -v '
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
