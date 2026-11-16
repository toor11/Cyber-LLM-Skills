# Detection Signals and Blue-Team Handoff

> Sub-skill: [`saml-assertion-attacks-assertion-forgery`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Assertion Consumer Service POSTs whose decoded SAMLResponse lacks a ds:Signature element but produce a session.
- NameID values containing XML comment markers or null bytes in authentication logs.
- Reuse of the same assertion ID or InResponseTo value across multiple sessions.
- Assertions consumed after their NotOnOrAfter timestamp relative to the service provider clock.
- SAMLResponse whose Audience or Recipient does not match this service provider entityID yet is accepted.
- Authenticated NameIDs with no corresponding issuance in the identity-provider audit trail.
- InResponseTo values matching no outstanding AuthnRequest the service provider generated.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Detection queries, triage, and hardening for this technique |
