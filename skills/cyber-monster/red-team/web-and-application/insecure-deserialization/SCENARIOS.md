# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`insecure-deserialization`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: GMP Deserialization Type Confusion Vulnerability [MyBB <= 1.8.3 RCE Vulnerability]

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** GMP Deserialization Type Confusion Vulnerability [MyBB - Write Date: 2015.4.28 > A type-confusion vulnerability was discovered in GMP deserialization with crafted object's __wakeup() magic method that can be abused for updating...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Remote Code Execution via Insecure Deserialization in Telerik UI

- **Provenance:** Source: `hackerone_disclosed_reports` | CVE: `CVE-2017-11317`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hello, I found an outdated version of Telerik Web UI (v2016.2.607.40) at the following URL: https://███/Telerik.Web.UI.WebResource.axd?type=rau.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Pickle deserialization vulnerability in XComs

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Apache Airflow, versions before 2.8.1, have a vulnerability that allows a potential attacker to poison the XCom data by bypassing the protection of "enable_xcom_pickling=False" configuration setting resulting in poisoned data after XCom deserialization.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: Novi Survey Insecure Deserialization Vulnerability

- **Provenance:** Source: `CYBER_CPT/cisa_kev`
- **Context / Surface:** CISA KEV Advisory (en)
- **Root Cause / Analysis:** CVE-2023-29492: Novi Survey Insecure Deserialization Vulnerability > **Jargon: CVE** — Common Vulnerabilities and Exposures, a standardized public identifier (like a serial number) for known security flaws.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 5: Basic Java Deserialization with ObjectInputStream readObject

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Basic Java Deserialization with ObjectInputStream readObject In this POST it's going to be explained an example using 'java.io.Serializable' **and why overriding 'readObject()' can be extremely dangerous if the incoming stream is attacker-controlled**.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 6: Java JSF ViewState Deserialization

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Java JSF ViewState Deserialization {{#include ../../banners/hacktricks-training.md}} Check the posts: - https://www.alphabot.com/security/blog/2017/java/Misconfigured-JSF-ViewStates-can-lead-to-severe-RCE-vulnerabilities.html - https://0xrick.github.io/hack-the-box/arkham/ {{#include...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 7: HTB: POV

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** HTB: POV This is my write-up for the medium HTB machine "POV". Topics covered include: ViewState deserialization leading to RCE, deserializing PSCredential objects and abusing SeDebugPrivilege for privesc.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 8: HITB-XCTF2018 Qualification Writeup

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** HITB-XCTF2018 Qualification Writeup 1. Python Revenge The vulnerable application was written in Python which keep user secret. At function getlocation they use unsafe serialize Pickle to deserialize data from user. They also limit system functions which prevent attacker can execute malicious on server.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.
