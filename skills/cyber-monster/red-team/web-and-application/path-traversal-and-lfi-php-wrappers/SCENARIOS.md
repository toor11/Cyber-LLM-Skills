# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`path-traversal-and-lfi-php-wrappers`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Authenticated Code Execution through Phar deserialization in CSV Importer as Shop manager in WooCommerce

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** This vulnerability is based on the following exploitation technique: https://blog.ripstech.com/2018/new-php-exploitation-technique/ It is easier to explain this vulnerability by having watched the PoC first: https://www.youtube.com/watch?v=mr3bAOIUwd4 Here is what's happening:...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: PHP filter chains: file read from error-based oracle

- **Provenance:** Source: `CYBER_CPT/govuln`
- **Context / Surface:** Go Vulnerability Advisory (None)
- **Root Cause / Analysis:** Incident de sécurité ? Suspicion de compromission ? 09 71 18 27 69csirt@synacktiv.com Aller au contenu principal Rechercher FRENCH Toggle Dropdown NOTRE OFFRE » Test d’intrusion / Red Team Réponse aux incidents Reverse-engineering Développement Produits CSIRT FORMATIONS NOUS REJOINDRE PUBLICATIONS...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: PHP filter_var shenanigans :: pwning.systems

- **Provenance:** Source: `CYBER_CPT/govuln`
- **Context / Surface:** Go Vulnerability Advisory (None)
- **Root Cause / Analysis:** PWNING.SYSTEMS ABOUT BUGS LINKS POSTS RSS PHP filter_var shenanigans [ 26 JAN 2022 ] // JORDY ZOMER // 7 MIN READ It is likely that we have all seen PHP filters that prevent us from encountering vulnerabilities.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 4: LFI2RCE via PHP Filters

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-22`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # LFI2RCE via PHP Filters {{#include ../../banners/hacktricks-training.md}} ## Intro This [**writeup** ] (https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d)explains that you can use **php filters to generate arbitrary content** as output. Which basically means that y
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Slasher

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-22`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** ## Introduction **Slasher** is a tiny PHP “eval sandbox.” Input is heavily escaped, then executed with 'eval()'. The intended defenses block obvious primitives (quotes, digits, arrays, '$', '_', '.' etc.). The bug is that **arbitrary PHP still executes**, so with a **quote-less,
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: OpenMage LTS: Phar Deserialization leads to Remote Code Execution

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-22`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # OpenMage LTS: Phar Deserialization leads to Remote Code Execution - **OSV ID**: GHSA-fg79-cr9c-7369 - **CVE**: CVE-2026-25524 - **CVSS**: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H - **Published**: 2026-04-21T14:32:48Z - **Modified**: 2026-04-21T14:50:20.508841Z - **Affected
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: image uploader

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-22`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # TryHackMe: Vulnversity Writeup ![\\"KISHORERAM\\"] (\\"https://miro.medium.com/v2/resize:fill:88:88/1*b7s0M9Cv1FA4KAQUReQ4fQ.jpeg\\") KISHORERAM · Follow 5 min read · Jul 18, 2023 \-- Listen Share Photo by Shahadat Rahman on Unsplash # Task 1: Deploy the machine > Connect via Op
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: PHP wrappers and streams

- **Provenance:** Source: `CYBER_CPT/hacker_recipes` | CWE: `CWE-22`
- **Context / Surface:** Source: hacker_recipes (en)
- **Root Cause / Analysis:** # PHP wrappers and streams ## data:// The attribute 'allow_url_include' must be set. This configuration can be checked in the 'php.ini' file. 'bash # Shell in base64 encoding echo "" / base64 # Accessing the log file via LFI curl --user-agent "PENT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
