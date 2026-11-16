# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ai-supply-chain-and-plugin-risk`](SKILL.md) | Family: **AI and LLM**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Plugin Credential Exceeds User Authority

- **Surface & Preconditions:** A CRM plugin authenticates with a service account that can read the whole tenant.
- **Root Cause & Impact:** Any user who can reach the plugin can retrieve records their own role forbids.
- **Verification & Fix:** Delegate the user's scopes to the plugin, test with a limited account, and confirm the broad records are no longer returned.

## Case 2: Manifest Changed After Approval

- **Surface & Preconditions:** The plugin's manifest is fetched at runtime and its description steers tool selection.
- **Root Cause & Impact:** A remote change makes the model call the plugin for tasks it was not approved for.
- **Verification & Fix:** Pin the manifest hash, require re-approval on change, and log manifest changes as a security event.
