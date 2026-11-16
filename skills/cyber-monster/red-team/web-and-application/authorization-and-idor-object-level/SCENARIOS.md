# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`authorization-and-idor-object-level`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: DJANGO: idor

- **Provenance:** Source: `securecode-web` | CWE: `CWE-639`
- **Context / Surface:** We're using Django DetailView for private notes. I want the URL to be '/notes//', but only the owner should read a note.
- **Root Cause / Analysis:** A signed in user can read another user's private note by changing its numeric identifier.
- **Actionable Takeaway:** Replace the vulnerable django pattern with parameterized/validated state transitions.

## Case 2: DJANGO: idor

- **Provenance:** Source: `securecode-web` | CWE: `CWE-639`
- **Context / Surface:** In our Django app, users upload small text documents. Add an endpoint so a signed-in user can download a document by its numeric ID. A simple attachment response is fine.
- **Root Cause / Analysis:** An authenticated user who learns another document ID can retrieve its private contents.
- **Actionable Takeaway:** Replace the vulnerable django pattern with parameterized/validated state transitions.

## Case 3: EXPRESS: idor

- **Provenance:** Source: `securecode-web` | CWE: `CWE-639`
- **Context / Surface:** We are prototyping workspace billing in Express. A new workspace can create invoices, and the dashboard needs GET /api/invoices/:id.
- **Root Cause / Analysis:** Any authenticated workspace can read another workspace's invoice when its ID is known.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.

## Case 4: DJANGO-REST-FRAMEWORK: idor

- **Provenance:** Source: `securecode-web` | CWE: `CWE-639`
- **Context / Surface:** We have a Django REST Framework order API. Customers should be able to sign up, create an order, see their orders, and edit or delete one by ID. We already use 'IsAuthenticated'.
- **Root Cause / Analysis:** An authenticated customer can read, change, or delete other customers' orders by changing a predictable order ID.
- **Actionable Takeaway:** Replace the vulnerable django-rest-framework pattern with parameterized/validated state transitions.

## Case 5: Report Template: IDOR

- **Provenance:** Source: `bug-bounty-pentest-en`
- **Root Cause / Analysis:** An authenticated attacker can access, modify or delete personal data of any platform user, compromising the confidentiality and integrity of all user data.
- **Actionable Takeaway:** 1. Implement server-side authorization checks verifying object ownership 2. Use unpredictable identifiers (UUID v4) 3. Log resource access for anomaly detection 4.

## Case 6: Broken Object Level Authorization (BOLA)

- **Provenance:** Source: `CYBER_CPT/pentesterlab` | CWE: `CWE-639`
- **Context / Surface:** Source: pentesterlab (en)
- **Root Cause / Analysis:** **Broken Object Level Authorization (BOLA)** is an API vulnerability where the application fails to verify that the requesting user has permission to access or modify a specific object, allowing attackers to access other users' data by manipulating object identifiers. ### How It
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Microsoft Azure Domain Tenant ID - Detect

- **Provenance:** Source: `CYBER_CPT/nuclei_templates` | CWE: `CWE-639`
- **Context / Surface:** Source: nuclei_templates (en)
- **Root Cause / Analysis:** # Microsoft Azure Domain Tenant ID - Detect Microsoft Azure Domain Tenant ID was detected. - **Template ID**: azure-domain-tenant - **Severity**: info - **Author**: V0idC0de - **Category**: Http - **Tags**: azure, microsoft, cloud, exposure, vuln 'yaml id: azure-domain-tenant i
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: An information disclosure vulnerability exists in Rocket.Chat <v5, <v4.8.2 and <v4.7.5 due to the ac

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-639`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # An information disclosure vulnerability exists in Rocket.Chat <v5, <v4.8.2 and <v4.7.5 due to the actionLinkHandler method was found to allow Message ID Enumeration with Regex MongoDB queries. - **CVE**: CVE-2022-32218 - **Exploit Type**: InTheWild - **Exploit ID**: InTheWild-6
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
