# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`web-app-fuzzing-and-automation`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: The login of Hotor Not is Vulnerable to bruteforce.

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** I was able to validate that The Login of HotorNot is Vulnerable to BruteForcing . Steps to reproduce: 1. https://hotornot.com/signin 2.Use Burp intruder attack for BruteForcing 3.Send as many requests you want.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: If rate limit is hit, IP address is leaked to anyone who tries to login

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: After the rate limit on https://bugzilla.mozilla.org/home on the login page is hit, bugzilla blocks the ip address. The next time someone logs in from any ip address, mozilla will say that the account has been locked and will list the ip address which broke the rate...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: 第八章 如何使用Burp Intruder

- **Provenance:** Source: `CYBER_CPT/burpsuite_guide` | CWE: `CWE-20`
- **Context / Surface:** Source: burpsuite_guide (zh)
- **Root Cause / Analysis:** ### 第八章 如何使用Burp Intruder Burp Intruder作为Burp Suite中一款功能极其强大的自动化测试工具，通常被系统安全渗透测试人员被使用在各种任务测试的场景中。 #### Intruder使用场景和操作步骤 在渗透测试过程中，我们经常使用Burp Intruder，它的工作原理是：Intruder在原始请求数据的基础上，通过修改各种请求参数，以获取不同的请求应答。每一次请求中，Intruder通常会携带一个或多个有效攻击载荷（Payload),在不同的位置进行攻击重放，通过应答数据的比对分析来获得需要的特征数据。Burp
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Rate Limit Bypass

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-20`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # Rate Limit Bypass ## Rate limit bypass techniques ### Exploring Similar Endpoints Attempts should be made to perform brute force attacks on variations of the targeted endpoint, such as '/api/v3/sign-up', including alternatives like '/Sing-up', '/SignUp', '/singup', '/api/v1/sig
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: PraisonAI: Unauthenticated WebSocket Endpoint Proxies to Paid OpenAI Realtime API Without Rate Limit

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-20`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary The '/media-stream' WebSocket endpoint in PraisonAI's call module accepts connections from any client without authentication or Twilio signature validation. Each connection opens an authenticated session to OpenAI's Realtime API using the server's API key. There are no
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: PinchTab: Unapplied Rate Limiting Middleware Allows Unbounded Brute-Force of API Token

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-20`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary PinchTab 'v0.7.7' through 'v0.8.4' contain incomplete request-throttling protections for auth-checkable endpoints. In 'v0.7.7' through 'v0.8.3', a fully implemented 'RateLimitMiddleware' existed in 'internal/handlers/middleware.go' but was not inserted into the produc
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: MinIO LDAP login brute-force via user enumeration and missing rate limit

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-20`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Impact MinIO AIStor's STS (Security Token Service) 'AssumeRoleWithLDAPIdentity' endpoint is vulnerable to LDAP credential brute-forcing due to two combined weaknesses: (1) distinguishable error responses that enable username enumeration, and (2) absence of rate limiting on au
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: Strapi Improper Rate Limiting vulnerability

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-20`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Strapi Improper Rate Limiting vulnerability - **OSV ID**: GHSA-24q2-59hm-rh9r - **CVE**: CVE-2023-38507 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L - **Published**: 2023-09-13T16:32:26Z - **Modified**: 2023-11-08T04:13:08.496788Z - **Affected Packages**: @strapi/ad
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
