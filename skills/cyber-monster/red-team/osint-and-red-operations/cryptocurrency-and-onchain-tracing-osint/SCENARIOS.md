# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`cryptocurrency-and-onchain-tracing-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Trail Followed Across a Bridge by Address String

- **Surface & Preconditions:** An analyst continues a trace on the destination chain using the same address.
- **Root Cause & Impact:** Bridge outputs go to a different address, so the continued trail belongs to an unrelated account.
- **Verification & Fix:** Re-trace from the bridge deposit event's recipient field, matching nonce and amount on the destination chain.

## Case 2: Service Deposit Reported as the Subject's Wallet

- **Surface & Preconditions:** A trace ends at an address labelled as an exchange deposit and the report names it as the subject's.
- **Root Cause & Impact:** The address is controlled by the service and shared across its users.
- **Verification & Fix:** Record the deposit as a terminal service point, name the service from corroborating evidence, and stop the user-level trail there.
