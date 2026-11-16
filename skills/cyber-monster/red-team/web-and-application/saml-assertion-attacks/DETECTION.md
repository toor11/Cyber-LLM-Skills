# Detection Signals and Blue-Team Handoff

> Sub-skill: [`saml-assertion-attacks`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Assertion Consumer Service POSTs where the decoded SAMLResponse contains more than one saml:Assertion element.
- SAMLResponse payloads carrying a DOCTYPE declaration that reach the service provider parser.
- ds:Reference URI values that do not match the ID of the Assertion whose NameID becomes the session subject.
- Successful single-sign-on logins for a NameID the upstream identity provider has no record of issuing.
- SAMLResponse submissions with no ds:Signature element that still produce an authenticated session.
- Reuse of the same assertion ID across multiple sessions or after its NotOnOrAfter timestamp.
- Service provider library versions predating the ruby-saml 1.18.0 / 1.12.4 fixes in the deployment inventory.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Detection queries, triage, and hardening for this technique |
