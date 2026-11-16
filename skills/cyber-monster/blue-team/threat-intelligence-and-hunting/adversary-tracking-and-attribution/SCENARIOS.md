# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`adversary-tracking-and-attribution`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: OSINT WRITEUP: Source: https://synoslabs.com/blog/apt-hunter-ctf-writeup/

- **Provenance:** Source: `osint-ctf-corpus-fr`
- **Context / Surface:** Investigation category: apt-tracking (fr)
- **Root Cause / Analysis:** Source: https://synoslabs.com/blog/apt-hunter-ctf-writeup/ APT Hunter CTF – Writeup – Synoslabs Skip to content Synoslabs Menu Close Services Pentest Web Pentest Wi-Fi Pentest Interne Pentest Mobile Pentest Externe Phishing Empreinte Numérique Évaluation des vulnérabilités Formations Articles Blog...
- **Actionable Takeaway:** Apply passive multi-source pivot verification and log timestamps/hashes for every OSINT hop.

## Case 2: Paperclip: Approval decision attribution spoofing via client-controlled 'decidedByUserId' in papercl

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-200`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary The approval-resolution endpoints ('POST /approvals/:id/approve', '/reject', '/request-revision') accept a client-supplied 'decidedByUserId' field in the request body and write it verbatim into the authoritative 'approvals.decidedByUserId' column — without cross-checki
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Paperclip: Approval decision attribution spoofing via client-controlled 'decidedByUserId' in papercl

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-200`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Paperclip: Approval decision attribution spoofing via client-controlled 'decidedByUserId' in paperclip server - **OSV ID**: GHSA-p7mm-r948-4q3q - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N - **Published**: 2026-04-16T22:48:46Z - **Modified**: 2026-04-16T23:04:48.568
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: wger has Stored XSS via Unescaped License Attribution Fields

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-200`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** # Stored XSS via Unescaped License Attribution Fields ## Summary The 'AbstractLicenseModel.attribution_link' property in 'wger/utils/models.py' constructs HTML strings by directly interpolating user-controlled fields ('license_author', 'license_title', 'license_object_url', 'lice
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Shai-Hulud 2.0 Aftermath: Trends, Victimology and Impact

- **Provenance:** Source: `CYBER_CPT/wiz_research` | CWE: `CWE-200`
- **Context / Surface:** Source: wiz_research (en)
- **Root Cause / Analysis:** Wiz Research and Wiz CIRT have been responding to the Shai-Hulud 2.0 incident (aka Sha1-Hulud) since news first broke on November 24, 2025. As of now we’re continuing to observe active spread, albeit at a significantly lower pace. This gives us an opportunity to step back and sha
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: PowerShell 给变量增加特性验证

- **Provenance:** Source: `CYBER_CPT/pstips` | CWE: `CWE-200`
- **Context / Surface:** Source: pstips (mixed)
- **Root Cause / Analysis:** # PowerShell 给变量增加特性验证 在PowerShell 2.0中，可以给变量增加特性验证，需要用到Set-Variable命令。在PowerShell 3.0 中，现在可以直接将验证特性应用到纯变量中了。比如下面的代码： ' [ValidateRange(1,100)][int]$num=3 $num=1 $num=50 $num=100 $num=0 $num=101 无法验证此变量，因为值 0 不是变量 num 的有效值。 所在位置 行:5 字符: 1 + $num=0 + ~~~~~~ + CategoryInfo : Metad
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Geopolitical Cyber-Detection Lures for Attribution with Microsoft Sentinel

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-200`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # Geopolitical Cyber-Detection Lures for Attribution with Microsoft Sentinel ### Summary There are tons of security event management (SIEM) solutions available these days, but this blog will focus on Microsoft Sentinel. Sentinel is easy to deploy, logs are inexpensive to retain,
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
