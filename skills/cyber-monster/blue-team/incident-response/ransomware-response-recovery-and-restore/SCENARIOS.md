# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ransomware-response-recovery-and-restore`](SKILL.md) | Family: **Incident Response**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: nginx-ui Backup Restore Allows Tampering with Encrypted Backups

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-778`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # nginx-ui Backup Restore Allows Tampering with Encrypted Backups - **OSV ID**: GHSA-fhh2-gg7w-gwpq - **CVE**: CVE-2026-33026 - **Published**: 2026-03-30T16:23:34Z - **Modified**: 2026-04-02T21:26:02.445231047Z - **Affected Packages**: github.com/0xJacky/Nginx-UI - **Ecosystem**:
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: nginx-ui Backup Restore Allows Tampering with Encrypted Backups

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-778`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary The 'nginx-ui' backup restore mechanism allows attackers to tamper with encrypted backup archives and inject malicious configuration during restoration. ## Details The backup format lacks a trusted integrity root. Although files are encrypted, the encryption key and IV
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: changedetection.io has Zip Slip vulnerability in the backup restore functionality

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-778`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary A Zip Slip vulnerability in the backup restore functionality allows arbitrary file overwrite via path traversal in uploaded ZIP archives. ### Details The application uses zipfile.extractall() without validating entry paths, allowing ../ sequences to escape the extract
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: changedetection.io has Zip Slip vulnerability in the backup restore functionality

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-778`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # changedetection.io has Zip Slip vulnerability in the backup restore functionality changedetection.io has Zip Slip vulnerability in the backup restore functionality - **OSV ID**: GHSA-25g8-2mcf-fcx9 - **CVE**: CVE-2026-29065 - **Published**: 2026-03-04T21:28:42Z - **Modified**:
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: A directory traversal issue in the Utils/Unzip module in Microweber through 1.1.20 allows an authent

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-778`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # A directory traversal issue in the Utils/Unzip module in Microweber through 1.1.20 allows an authenticated attacker to gain remote code execution via the backup restore feature. To exploit the vulnera - **CVE**: CVE-2020-28337 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Squidex is an open source headless CMS and content management hub. Affected versions are subject to

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-778`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Squidex is an open source headless CMS and content management hub. Affected versions are subject to an arbitrary file write vulnerability in the backup restore feature which allows an authenticated at - **CVE**: CVE-2023-46253 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
