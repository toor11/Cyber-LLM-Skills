# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`insecure-deserialization-java-gadgets`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: MobileIron Unauthenticated RCE on mdm.qiwi.com with WAF bypass

- **Provenance:** Source: `hackerone_disclosed_reports` | CVE: `CVE-2020-15505`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Last week, details about 3 CVEs affecting **MobileIron MDM** product were disclosed. When combined, an attacker can achieve unauthenticated remote code execution with arbitrary Java deserialization vector : - CVE-2020-15505 - Remote Code Execution - CVE-2020-15506 -...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Java Deserialization RCE via JBoss JMXInvokerServlet/EJBInvokerServlet on card.starbucks.in

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** I found an open JMXInvokerServlet/EJBInvokerServlet and normally I should be able to get a shell just by doing that. However I think due to some egress filtering on the box I've been having issues getting a shell to run.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: fabric-sdk-java has ObjectInputStream.readObject() without ObjectInputFilter, which allows Java dese

- **Provenance:** Source: `CYBER_CPT/gh_security_lab`
- **Context / Surface:** CodeQL / Audit Case (en)
- **Root Cause / Analysis:** Summary This advisory covers the deprecated 'fabric-sdk-java' client SDK. 'Channel.java' implements 'readObject()' and exposes 'deSerializeChannel()' which call 'ObjectInputStream.readObject()' on untrusted byte arrays without configuring an 'ObjectInputFilter'.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 4: Basic Java Deserialization with ObjectInputStream readObject

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Basic Java Deserialization with ObjectInputStream readObject In this POST it's going to be explained an example using 'java.io.Serializable' **and why overriding 'readObject()' can be extremely dangerous if the incoming stream is attacker-controlled**.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 5: Java DNS Deserialization, GadgetProbe and Java Deserialization Scanner

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Java DNS Deserialization, GadgetProbe and Java Deserialization Scanner {{#include ../../banners/hacktricks-training.md}} DNS request on deserialization The class 'java.net.URL' implements 'Serializable', this means that this class can be serialized.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 6: Java SignedObject-gated Deserialization and Pre-auth Reachability via Error Paths

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Java SignedObject-gated Deserialization and Pre-auth Reachability via Error Paths This page documents a common "guarded" Java deserialization pattern built around java.security.SignedObject and how seemingly unreachable sinks can become pre-auth reachable via error-handling flows.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 7: Java Deserialization Vulnerability, CVE-2015–7501 . Tony the Tiger: TryHackMe Walkthrough

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Java Deserialization Vulnerability, CVE-2015-7501: Tony the Tiger TryHackMe Walkthrough Learn how to use a Java Serialisation attack in this boot-to-root. Practice Linux, SHELL=/bin/bash script -q /dev/null, find / -type f -name 2>/dev/null, grep -R "string" 2>/dev/null, sudo find .
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 8: Hack The Box — writeup on Arkham

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Hack The Box — writeup on Arkham Hello world! Arkham has finally retired and is time for me to release this writeup. It is a tricky box especially the Java Deserialization part and the PowerShell Invoke-Command part but other than that, it is a great box to play with.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.
