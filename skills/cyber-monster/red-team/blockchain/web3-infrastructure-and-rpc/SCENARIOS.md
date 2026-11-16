# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`web3-infrastructure-and-rpc`](SKILL.md) | Family: **Blockchain**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Node Reachable With an Unlocked Account

- **Surface & Preconditions:** A node binds to all interfaces with the personal namespace enabled and one account unlocked.
- **Root Cause & Impact:** Any client that reaches the port can sign with that account, so the balance is at risk without any contract bug.
- **Verification & Fix:** Bind to loopback, drop the personal namespace, use an external signer, and verify with the account and admin probes.

## Case 2: Dapp Loading a Mutable Provider Script

- **Surface & Preconditions:** The front-end loads its wallet provider from a third-party URL with no integrity attribute.
- **Root Cause & Impact:** Whoever controls that URL can change what the page asks users to sign.
- **Verification & Fix:** Pin the script with a subresource integrity hash or vendor it, add a CSP that restricts script origins, and record the change.
