# Multi-Dataset Provenance Log

> Sub-skill: [`session-and-token-lifecycle`](SKILL.md) | Family: **Web and Application**

Case labels below are stored in this file. The procedure is in [`SKILL.md`](SKILL.md).

## In-file case labels

| Tag | What this file already states |
|---|---|
| CWE-640 | flask - password reset token lifecycle |
| CWE-1392 | java - default admin credentials |
| CWE-347 | aspnet-core - jwt signature not verified |
| CWE-308 | express - mfa step bypass |
| CWE-321 | php - jwt hardcoded hmac key |
| CWE-640 | spring-boot - password reset token lifecycle |
| CWE-306 | aspnet-core - unauthenticated first run admin setup |
| CWE-784 | express - remember me token |
| CWE-601 | JAKARTA-SERVLET: post login open redirect |
| CWE-603 | EXPRESS: client asserted biometric login |
| CWE-307 | SPRING-BOOT: credential stuffing login throttling |
| CWE-613 | FLASK: session scope |
| Secure flag | Omit the Secure flag to allow cookies to be sent over both HTTP and HTTPS, increasing the... |
| session management | The token is rotated after each session and has a limited lifetime. |
| HSTS | Disabling cookies entirely and using URL parameters to track sessions. |
| SessionFixation | Keep using the existing session identifier after user login for performance reasons. |
| Session Management | Ensure cookies that contain user information are not signed to provide greater transparency. |
| Session Management | Longer session timeouts are preferred for public forums and home banking applications to... |
| Cookie Security | Set-Cookie: sessionId=abc123; Secure; HttpOnly; SameSite=Strict; |
| Session Hijacking | Implementing secure, HttpOnly, and SameSite flags for cookies. |
| explain | CVE-2023-24424 describes a Session Fixation flaw affecting Jenkins Openid Connec |
| explain | Triage summary for CVE-2025-51990: - Product: XWiki – Stored Cross-Site Scriptin |
| explain | Answer: C) path traversal. Why: Apache Flink 1.5.1 introduced a REST handler tha |
| explain | CVE-2025-51990 affects XWiki – Stored Cross-Site Scripting (XSS) and is classed |
| explain | CVE-2020-36913 describes a Session Fixation flaw. NVD describes CVE-2020-36913 a |
| explain | OpenVPN Access Server is affected by CVE-2017-5868, a session management flaw fl |
| explain | CVE-2017-10890 describes a Session Fixation flaw affecting Sharp rx-v200 Firmwar |
| explain | CVE-2021-42761 describes a Session Fixation flaw affecting Fortinet Fortiweb. Th |
| identify | Overview Session cookies keep users logged in. Flags like HttpOnly, Secure, and |
| identify | There are a small number of session management attacks, some related to the user |
