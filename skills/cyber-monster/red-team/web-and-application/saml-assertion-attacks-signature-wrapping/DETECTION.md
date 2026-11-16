# Detection Signals and Blue-Team Handoff

> Sub-skill: [`saml-assertion-attacks-signature-wrapping`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- SAMLResponse documents whose assertion count exceeds one at the Assertion Consumer Service.
- ds:Reference URI values pointing to an element nested inside ds:Object or samlp:Extensions rather than a top-level Assertion.
- Multiple XML elements carrying identical ID attribute values in a single response.
- Namespace prefix declarations redeclared between the signed element and the element whose NameID is logged.
- Successful logins where the signed assertion ID differs from the assertion ID recorded as the session source.
- SAML library versions below ruby-saml 1.18.0 / 1.12.4 or omniauth-saml 2.2.3 / 1.10.6 in the asset inventory.
- A burst of Assertion Consumer Service POSTs from one client cycling through structurally different multi-assertion layouts.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Detection queries, triage, and hardening for this technique |
