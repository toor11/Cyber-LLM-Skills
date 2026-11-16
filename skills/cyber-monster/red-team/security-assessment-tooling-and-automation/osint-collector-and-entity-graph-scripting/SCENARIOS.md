# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`osint-collector-and-entity-graph-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Two Entities Merged on a Shared Display Name

- **Surface & Preconditions:** A graph shows one node for an individual with records from two unrelated sources.
- **Root Cause & Impact:** The collector keyed on display name, and both records happened to share it.
- **Verification & Fix:** Split the node, attach the source and timestamp to each record, and require an identifier match before re-joining.

## Case 2: Record Changed and the Original Was Lost

- **Surface & Preconditions:** A registrar record is cited in a report but the source now shows different registrant data.
- **Root Cause & Impact:** The collector overwrote the earlier row, so no one can show what was observed at collection time.
- **Verification & Fix:** Re-collect with append-only storage and hashes, and cite the timestamped observation rather than the live page.
