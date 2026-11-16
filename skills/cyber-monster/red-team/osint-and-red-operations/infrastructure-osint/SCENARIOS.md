# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`infrastructure-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Shared Host Attributed to the Client

- **Surface & Preconditions:** A scan of an address hosting the client's website lists dozens of unrelated services as client infrastructure.
- **Root Cause & Impact:** The address is a shared platform, and the services belong to other tenants.
- **Verification & Fix:** Attribute by announced prefixes and certificate subject, mark the shared-host name as hosted elsewhere, and rescan only within attributed ranges.

## Case 2: CT-Only Hostname Reported as Live

- **Surface & Preconditions:** A hostname from certificate transparency is listed as an asset although it never resolves.
- **Root Cause & Impact:** CT records persist after a name is withdrawn, so presence there is historical evidence, not current state.
- **Verification & Fix:** Record the issuance date, attempt resolution, and report the name as historical when it no longer resolves.
