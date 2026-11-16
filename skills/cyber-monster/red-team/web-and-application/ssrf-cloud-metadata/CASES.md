# Multi-Dataset Provenance Log

> Sub-skill: [`ssrf-cloud-metadata`](SKILL.md) | Family: **Web and Application**

Case labels below are stored in this file. The procedure is in [`SKILL.md`](SKILL.md).

## In-file case labels

| Tag | What this file already states |
|---|---|
| - | SSRF in Exchange leads to ROOT access in all instances |
| CWE-918 | IMDS Abused: Hunting Rare Behaviors to Uncover Exploits |
| CWE-918 | Ech0: Unauthenticated SSRF in GetWebsiteTitle allows access to internal services and cloud... |
| CWE-918 | Craft CMS: Cloud Metadata SSRF Protection Bypass via IPv6 Resolution |
| CWE-918 | Craft CMS has Cloud Metadata SSRF Protection Bypass via DNS Rebinding |
| CWE-918 | Craft CMS: Cloud Metadata SSRF Protection Bypass via IPv6 Resolution |
| CWE-918 | pyLoad: Server-Side Request Forgery via Download Link Submission Enables Cloud Metadata... |
| explain | Overview Importantly, but this time the CSS will be imported from com/rpo/index. |
| explain | Overview Alternate IP encodings, DNS rebinding, redirects, IPv6, and obscure sch |
| explain | From a developer's point of view, CVE-2024-29030 happens because Memos follows a |
| explain | From a developer's point of view, CVE-2025-10211 happens because ChanCMS follows |
| explain | From a developer's point of view, CVE-2019-16932 happens because Visualizer foll |
| explain | From a developer's point of view, CVE-2024-54385 happens because Radio Player fo |
| explain | The server-side fetch of 'http://127.0.0.1:5000/config' returned the internal co |
| explain | Unauthenticated attackers can perform server-side request forgery to query and m |
| identify | Overview SSRF makes the server fetch a URL the attacker controls, reaching inter |
| identify | Implement strict URL allowlist, block private IP ranges, disable unnecessary pro |
| remediate | The gap is that my code resolves DNS twice. Look at the flow: 1. My adapter call |
| remediate | Unauthenticated attackers can force the server to make arbitrary requests via SS |
| remediate | Allow-list schemes/hosts; block private IP ranges and cloud metadata endpoints; |
| remediate | **Vulnerability Class:** ssrf **CWE:** CWE-918 **Weakness:** Server-Side Request |
| remediate | Overview Alternate IP encodings, DNS rebinding, redirects, IPv6, and obscure sch |
| impact | **Vulnerability Class:** ssrf **CWE:** CWE-918 **Weakness:** Server-Side Request |
| impact | **Full-read SSRF** in the avatar 'url' parameter. **PoC — escalate to AWS IMDSv1 |
