# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`infrastructure-osint-host-and-service-discovery`](SKILL.md) | Family: **OSINT and Red Operations**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Brand Match Reported as Client Infrastructure

- **Surface & Preconditions:** A dataset search for a brand name returns forty hosts, all listed as the client's.
- **Root Cause & Impact:** Page text on unrelated hosts mentions the brand, and none of the addresses are in the client's prefixes.
- **Verification & Fix:** Re-run with a `net:` filter over announced prefixes, add certificate evidence, and drop results outside those ranges.

## Case 2: Stale Banner Reported as Live Service

- **Surface & Preconditions:** The inventory lists a database service that the dataset recorded eight months ago.
- **Root Cause & Impact:** No current observation was made, and the service was decommissioned.
- **Verification & Fix:** Apply the freshness filter, attempt one current connection, and record the dataset date beside the confirmation result.
