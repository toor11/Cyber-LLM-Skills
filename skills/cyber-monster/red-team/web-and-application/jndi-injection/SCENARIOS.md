# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`jndi-injection`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: LogForge

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-917`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** LogForge was a UHC box that HTB created entirely focused on Log4j / Log4Shell. To start, there’s an Orange Tsai attack against how Apache is hosting Tomcat, allowing the bypass of restrictions to get access to the manager page. From there, I’ll exploit Log4j to get a shell as the
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Using Java Deserialization to exploit log4shell — LogForge, HTB

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-917`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Using Unsafe Java Deserialization to exploit log4shell — LogForge, HTB This is primarily a walkthrough for “LogForge” HTB machine. I’ve already explored exploiting log4shell through the classpath loading method here. Here we exploit the box using JNDI-Exploit-Kit and YsoSerial,
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: JNDI - Java Naming and Directory Interface & Log4Shell

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-917`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # JNDI - Java Naming and Directory Interface & Log4Shell ## Basic Information JNDI, integrated into Java since the late 1990s, serves as a directory service, enabling Java programs to locate data or objects through a naming system. It supports various directory services via servi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Log4Shell — Intrusion Analysis

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-917`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Log4Shell — Intrusion Analysis In my previous post I explored the offensive side of Log4Shell, where we achieved RCE on TryHackMe’s Solar box — Solar (log4shell) — TryHackMe In this post we explore the defensive side of things, where we explore the following Network and System
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: TryHackMe — Solar, exploiting log4j

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-917`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # TryHackMe — Solar, exploiting log4j The talk of the hour, the severe vulnerability log4j , today I will walk you through the TryHackMe room — Solar, exploiting log4j and hopefully brief you a bit about the vulnerability. Big Thanks to JohnHammond and TryHackeMe for this awesome
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Apache Log4Shell Analysis

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-917`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Apache Log4Shell Analysis ![\\"Kyro\\"] (\\"https://miro.medium.com/v2/resize:fill:88:88/1*apMjliaZ52dcWOtr1T8zww@2x.jpeg\\") ![\\"System] (\\"https://miro.medium.com/v2/resize:fill:48:48/1*gncXIKhx5QOIX0K9MGcVkg.jpeg\\") Kyro · Follow Published in System Weakness · 12 min read ·
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
