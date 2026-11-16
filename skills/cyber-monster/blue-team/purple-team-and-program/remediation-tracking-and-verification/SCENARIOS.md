# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`remediation-tracking-and-verification`](SKILL.md) | Family: **Purple Team and Program**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Vikunja has a Link Share Delete IDOR — Missing Project Ownership Check Allows Cross-Project Link Sha

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-693`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary The 'DELETE /api/v1/projects/:project/shares/:share' endpoint does not verify that the link share belongs to the project specified in the URL. An attacker with admin access to any project can delete link shares from other projects by providing their own project ID comb
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Apple macOS/iOS - ReportCrash mach port Replacement due to Failure to Respect MIG Ownership Rules

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-693`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # Apple macOS/iOS - ReportCrash mach port Replacement due to Failure to Respect MIG Ownership Rules EKU-ID: 48505 CVE: CVE-2018-4206 Author: Google Security Research Published: 2018-04-30 'c /* ReportCrash is the daemon responsible for making crash dumps of crashing userspace p
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Open WebUI's process_files_batch() endpoint missing ownership check, allows unauthorized file overwr

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-693`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary Any authenticated user can overwrite any file's content by ID through the 'POST /api/v1/retrieval/process/files/batch' endpoint. The endpoint performs no ownership check, so a regular user with read access to a shared knowledge base can obtain file UUIDs via 'GET /api
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Grant ownership

- **Provenance:** Source: `CYBER_CPT/hacker_recipes` | CWE: `CWE-693`
- **Context / Surface:** Source: hacker_recipes (en)
- **Root Cause / Analysis:** # Grant ownership This abuse can be carried out when controlling an object that has 'WriteOwner' or 'GenericAll' over any object. The attacker can update the owner of the target object. Once the object owner has been changed to a principal the attacker controls, the attacker may
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Vikunja has a Link Share Delete IDOR — Missing Project Ownership Check Allows Cross-Project Link Sha

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-693`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Vikunja has a Link Share Delete IDOR — Missing Project Ownership Check Allows Cross-Project Link Share Deletion - **OSV ID**: GHSA-f95f-77jx-fcjc - **CVE**: CVE-2026-33700 - **Published**: 2026-03-25T21:21:20Z - **Modified**: 2026-03-26T21:11:20.245723Z - **Affected Packages**:
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Froxlor has an Email Sender Alias Domain Ownership Bypass via Wrong Array Index Allows Cross-Custome

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-693`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary In 'EmailSender::add()', the domain ownership validation for full email sender aliases uses the wrong array index when splitting the email address, passing the local part instead of the domain to 'validateLocalDomainOwnership()'. This causes the ownership check to alwa
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
