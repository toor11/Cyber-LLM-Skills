# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`xxe`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: SPRING-BOOT: xxe

- **Provenance:** Source: `securecode-web` | CWE: `CWE-611` | CVE: `CVE-2013-4152`
- **Context / Surface:** We're building a settings service on Spring Boot 3.5 / Java 21. Admins want to export their workspace settings as an XML file from our old desktop tool and upload it to the new...
- **Root Cause / Analysis:** In-band file read and SSRF from a single unauthenticated-or-low-privilege import request, bounded by the service account's file and network reach; no code execution.
- **Actionable Takeaway:** Replace the vulnerable spring-boot pattern with parameterized/validated state transitions.

## Case 2: OSINT WRITEUP: Oz Medileak2 Raw

- **Provenance:** Source: `osint-ctf-corpus-fr`
- **Context / Surface:** Investigation category: medileak (fr)
- **Root Cause / Analysis:** <link rel="icon" type="image/png" sizes="32x32" href="/icons/favicon-32x32.png" /> <link rel="icon" type="image/png" sizes="16x16" href="/icons/favicon-16x16.png" /> <meta name="viewport" content="width=device-width, initial-scale=1.0...
- **Actionable Takeaway:** Apply passive multi-source pivot verification and log timestamps/hashes for every OSINT hop.

## Case 3: Report Template: XXE

- **Provenance:** Source: `bug-bounty-pentest-en`
- **Root Cause / Analysis:** An attacker can read arbitrary files on the server (credentials, configuration, source code), make SSRF requests to internal services and potentially cause denial of service (Billion Laughs).
- **Actionable Takeaway:** 1. Disable DTDs and external entities in XML parser 2. Use JSON as data format instead of XML 3. Update XML libraries 4. Implement XML schema validation (XSD)

## Case 4: Blind OOB XXE At "http://ubermovement.com/"

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Test Summary : - POST data was set to <!DOCTYPE dtgmlf6 [ ]> &dtgmlf6ent; An HTTP request was initiated for the domain http://122.180.248.81/ which...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: Periscope iOS app CSRF in follow action due to deeplink

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary This issue is mainly in the Periscope iOS app against CSRF follow action using deeplink. as the report #583987 the CSRF work on iOS app POC 1 QR code to follow periscope profile 'pscp://user/periscopeco/follow ' ███████ POC2 by kunal94 <a...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: [rev-app.informatica.com] - XXE

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** 1. Open file xxe.xlsx like zip-archive 2. Read file xxe.xlsx\xl\worksheets\sheet1.xml In file I wrote XXE payload: ]> Then, i went to https://rev-app.informatica.com and made new project and...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: RCE via Local File Read -> php unserialization-> XXE -> unpickling

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** It was possible to escalate to Remote Code Execution via different bugs such as local file read, php object injection, XML External Entity and Un-Pickling of Python serialized object.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: Citrix StoreFront Server XML External Entity (XXE) Processing Vulnerability

- **Provenance:** Source: `CYBER_CPT/cisa_kev`
- **Context / Surface:** CISA KEV Advisory (en)
- **Root Cause / Analysis:** CVE-2019-13608: Citrix StoreFront Server XML External Entity (XXE) Processing Vulnerability > **Jargon: CVE** — Common Vulnerabilities and Exposures, a standardized ID system for publicly known security flaws.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.
