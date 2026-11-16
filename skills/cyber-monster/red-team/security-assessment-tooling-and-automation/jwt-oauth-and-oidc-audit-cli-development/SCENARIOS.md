# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`jwt-oauth-and-oidc-audit-cli-development`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Verifier Accepts a Sibling Issuer's Token

- **Surface & Preconditions:** A deployment's verifier checks signature and expiry but not `iss`, so a token from the staging issuer is accepted in production.
- **Root Cause & Impact:** Both environments share a signing key set; only the issuer distinguishes them.
- **Verification & Fix:** Decode the same token with the production issuer and with the staging issuer, and show that only the explicit `issuer=` argument rejects the second.

## Case 2: Public Client Without PKCE Enforcement

- **Surface & Preconditions:** The discovery document advertises `S256`, but the authorization server accepts a code exchange with no verifier.
- **Root Cause & Impact:** Advertising PKCE support is not enforcement; the server-side check is what matters.
- **Verification & Fix:** Exchange a code with and without the verifier and compare the token endpoint responses; an accepted exchange without a verifier is the finding.
