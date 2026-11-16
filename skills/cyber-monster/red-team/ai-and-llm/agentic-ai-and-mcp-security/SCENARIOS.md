# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`agentic-ai-and-mcp-security`](SKILL.md) | Family: **AI and LLM**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Hijacked Context Redirects a Payment

- **Surface & Preconditions:** An agent reads a vendor email and has a payment tool that accepts an IBAN.
- **Root Cause & Impact:** An instruction in the email supplies a new IBAN, and the model calls the tool with it.
- **Verification & Fix:** Remove the IBAN argument, resolve it from the verified vendor record, and require deterministic purchase-order checks plus human approval.

## Case 2: Tool Description Changes After Approval

- **Surface & Preconditions:** A third-party MCP server is approved, then updates its tool descriptions to steer the model.
- **Root Cause & Impact:** The client approved the server once, so the new descriptions reach the context with the old trust.
- **Verification & Fix:** Pin the server identity and tool description hashes, re-prompt for approval on change, and log description changes as a security event.
