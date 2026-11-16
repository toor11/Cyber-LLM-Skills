# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`secure-code-review-language-specific-review`](SKILL.md) | Family: **Application Security**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Using Java Deserialization to exploit log4shell — LogForge, HTB

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-20`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Using Unsafe Java Deserialization to exploit log4shell — LogForge, HTB This is primarily a walkthrough for “LogForge” HTB machine. I’ve already explored exploiting log4shell through the classpath loading method here. Here we exploit the box using JNDI-Exploit-Kit and YsoSerial,
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: How to exploit the DotNetNuke Cookie Deserialization

- **Provenance:** Source: `CYBER_CPT/awesome_web_security` | CWE: `CWE-20`
- **Context / Surface:** Source: awesome_web_security (en)
- **Root Cause / Analysis:** # How to exploit the DotNetNuke Cookie Deserialization We looked at around 300 DotNetNuke deployments in the wild and discovered that **one in five installations was vulnerable** to CVE-2017-9822. That includes governmental and banking websites. **Later edit [June 11, 2020]:** As
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Java Deserialization Vulnerability, CVE-2015–7501 . Tony the Tiger: TryHackMe Walkthrough

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-20`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Java Deserialization Vulnerability, CVE-2015-7501: Tony the Tiger TryHackMe Walkthrough Learn how to use a Java Serialisation attack in this boot-to-root. Practice Linux, SHELL=/bin/bash script -q /dev/null, find / -type f -name 2>/dev/null, grep -R "string" 2>/dev/null,
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HOW TO EXPLOIT LIFERAY CVE-2020-7961 : QUICK JOURNEY TO POC

- **Provenance:** Source: `CYBER_CPT/awesome_web_security` | CWE: `CWE-20`
- **Context / Surface:** Source: awesome_web_security (en)
- **Root Cause / Analysis:** # How to exploit Liferay CVE-2020-7961 : quick journey to PoC Liferay is one of the most known CMS written in Java that we encounter sometimes during assessment. Last week, we stumbled on the blog post from Code White Security entitled "Liferay Portal JSON Web Service RCE Vulnera
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Exploiting Node.js deserialization bug for Remote Code Execution

- **Provenance:** Source: `CYBER_CPT/awesome_web_security` | CWE: `CWE-20`
- **Context / Surface:** Source: awesome_web_security (en)
- **Root Cause / Analysis:** # Exploiting Node.js deserialization bug for Remote Code Execution ### **tl;dr** Untrusted data passed into 'unserialize()' function in node-serialize module can be exploited to achieve arbitrary code execution by passing a serialized JavaScript Object with an Immediately invoked
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Day 8: Insecure deserialization

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-20`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Day 8: Insecure deserialization > Please note: This is part eight of a 10-part series on TryHackMe OWASP top 10 room Serialization is whereby objects are converted into byte streams for storage or transmission into memory or the database. The reverse process is deserialization.
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
