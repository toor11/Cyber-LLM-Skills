# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`dns-rebinding-attacks`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: DNS rebinding in --inspect (insufficient fix of CVE-2022-32212 affecting macOS devices)

- **Provenance:** Source: `hackerone_disclosed_reports` | CVE: `CVE-2022-32212`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** The fix for CVE-2022-32212, covered the cases for routable IP addresses, however, there exists a specific behavior on macOS devices when handling the 'http://0.0.0.0' URL that allows an attacker-controlled DNS server to bypass the DNS rebinding protection by resolving hosts in...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: DNS Rebinding in Browser

- **Provenance:** Source: `CYBER_CPT/govuln`
- **Context / Surface:** Go Vulnerability Advisory (None)
- **Root Cause / Analysis:** 微信又改版了，为了我们能一直相见 你的加星和在看对我们非常重要 点击“长亭安全课堂”——主页右上角——设为星标🌟 期待与你的每次见面～ 在浏览器场景下的 DNS 重绑定攻击有什么不一样？ 最近 Chrome 的正在推广（https://developer.chrome.com/blog/private-network-access-preflight/）的PNA(Private Network Access) ：https://wicg.github.io/private-network-access/策略真的能完全防御吗？ DNS重绑定...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: Ray is vulnerable to Critical RCE via Safari & Firefox Browsers through DNS Rebinding Attack

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-350`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Ray is vulnerable to Critical RCE via Safari & Firefox Browsers through DNS Rebinding Attack - **OSV ID**: GHSA-q279-jhrf-cc6v - **CVE**: CVE-2025-62593 - **Published**: 2025-11-26T19:35:23Z - **Modified**: 2026-02-04T04:12:45.563534Z - **Affected Packages**: ray - **Ecosystem*
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Glances's REST/WebUI Lacks Host Validation and Remains Exposed to DNS Rebinding

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-350`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary Glances recently added DNS rebinding protection for the MCP endpoint, but the main REST/WebUI FastAPI application still accepts arbitrary 'Host' headers and does not apply 'TrustedHostMiddleware' or an equivalent host allowlist. As a result, the REST API, WebUI, and to
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Craft CMS has Cloud Metadata SSRF Protection Bypass via DNS Rebinding

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-350`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Craft CMS has Cloud Metadata SSRF Protection Bypass via DNS Rebinding - **OSV ID**: GHSA-gp2f-7wcm-5fhx - **CVE**: CVE-2026-27127 - **Published**: 2026-02-23T22:16:01Z - **Modified**: 2026-02-28T05:14:37.829487Z - **Affected Packages**: craftcms/cms - **Ecosystem**: Packagist #
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: DNS Rebinding

- **Provenance:** Source: `CYBER_CPT/pentesterlab` | CWE: `CWE-350`
- **Context / Surface:** Source: pentesterlab (en)
- **Root Cause / Analysis:** **DNS Rebinding** is an attack that exploits DNS and browser security models to bypass Same-Origin Policy, allowing malicious websites to access internal network resources or localhost services. ### How It Works The attacker controls a domain with a DNS server that returns changi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Transmission - RPC DNS Rebinding

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-350`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # Transmission - RPC DNS Rebinding / EKU-ID: 47677 / CVE: CVE-2018-5702 / OSVDB-ID: / / --- / --- / --- / / Author: Google Security Research / Published: 2018-01-11 / Verified: / The transmission bittorrent client uses a client/server architecture, the user interface is the clien
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: Ray is vulnerable to Critical RCE via Safari & Firefox Browsers through DNS Rebinding Attack

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-350`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** # Summary Developers working with Ray as a development tool can be exploited via a critical RCE vulnerability exploitable via Firefox and Safari. Due to the longstanding [decision] (https://docs.ray.io/en/releases-2.51.1/ray-security/index.html) by the Ray Development team to not
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
