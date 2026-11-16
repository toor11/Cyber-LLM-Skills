# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`insecure-deserialization-python-and-ruby-gadgets`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Unsafe yaml load can lead to remote code execution

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** TL;DR Yaml.load() has the ability to construct an arbitrary Python object. This is dangerous if you receive a YAML document from an untrusted source.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Pickle deserialization vulnerability in XComs

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Apache Airflow, versions before 2.8.1, have a vulnerability that allows a potential attacker to poison the XCom data by bypassing the protection of "enable_xcom_pickling=False" configuration setting resulting in poisoned data after XCom deserialization.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: HTB: DevOops

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-502`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** DevOops was a really fun box that did a great job of providing interesting challenges that weren’t too difficult to solve. I’ll show how to gain access using XXE to leak the users SSH key, and then how I get root by discovering the root SSH key in an old git commit. In Beyond Roo
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Pipecat: Remote Code Execution by Pickle Deserialization Through LivekitFrameSerializer

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-502`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Pipecat: Remote Code Execution by Pickle Deserialization Through LivekitFrameSerializer - **OSV ID**: GHSA-c2jg-5cp7-6wc7 - **CVE**: CVE-2025-62373 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H - **Published**: 2026-04-23T21:15:42Z - **Modified**: 2026-04-23T21:33:55
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Canape

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-502`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Canape is one of my favorite boxes on HTB. There is a flask website with a pickle deserialization bug. I find that bug by taking advantage of an exposed git repo on the site. With a user shell, we can exploit CouchDB to gain admin access, where we get homer’s password. I went dow
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Python Deserialization

- **Provenance:** Source: `CYBER_CPT/payloads_all_the_things` | CWE: `CWE-502`
- **Context / Surface:** Source: payloads_all_the_things (en)
- **Root Cause / Analysis:** # Python Deserialization > Python deserialization is the process of reconstructing Python objects from serialized data, commonly done using formats like JSON, pickle, or YAML. The pickle module is a frequently used tool for this in Python, as it can serialize and deserialize comp
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Pickle Store

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-502`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # Pickle Store - 223 Points / 109 Solves ## Background New pickles just dropped! Check out the store. [https://pickles-web.challenges.ctf.ritsec.club/] (https://pickles-web.challenges.ctf.ritsec.club/) ![] (<https://raw.githubusercontent.com/siunam321/CTF-Writeups/main/RITSEC-CTF-2
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: Jar

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-502`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # HackTheBox - Broker ![\\"jniket\\"] (\\"https://miro.medium.com/v2/resize:fill:88:88/1*3Ioi5ntw-Q8OX2tO9Oy3pQ.png\\") jniket · Follow 5 min read · Nov 19, 2023 \-- Listen Share # Summary * OS —Linux * Difficulty — Easy * Released — November 9, 2023 * Creator — TheCyberGeek * Mac
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
