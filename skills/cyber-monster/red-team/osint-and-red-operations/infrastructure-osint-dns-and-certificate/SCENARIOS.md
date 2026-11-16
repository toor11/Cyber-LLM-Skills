# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`infrastructure-osint-dns-and-certificate`](SKILL.md) | Family: **OSINT and Red Operations**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Old Name Reported as an Asset

- **Surface & Preconditions:** A passive DNS record from 2021 is cited as evidence that the organisation operates an address.
- **Root Cause & Impact:** The name has been withdrawn and the address reassigned, so the record describes history.
- **Verification & Fix:** Query the authoritative server, record NXDOMAIN, and present the name with its active window from certificate dates.

## Case 2: Wildcard Zone Inflates the Name List

- **Surface & Preconditions:** A dictionary of a thousand labels all resolve under the zone, and every result is listed.
- **Root Cause & Impact:** The zone has a wildcard record, so every query returns an address regardless of the label.
- **Verification & Fix:** Test a random label, discover the wildcard, and discard resolved-on-wildcard results; report only names with independent evidence.
