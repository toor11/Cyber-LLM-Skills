# Detection Signals and Blue-Team Handoff

> Sub-skill: [`open-redirect-allowlist-bypass`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Redirect-route access logs where the destination host string contains the brand as a subdomain label followed by a foreign apex.
- Location headers whose authority includes an `@` character, indicating a userinfo-form destination.
- Requests carrying percent-encoded `%2f%2f` or `https:%2f%2f` sequences in the redirect parameter.
- Mismatch between the host logged by the application allowlist and the host resolved in the outbound navigation.
- A spike of 302 responses to one route whose Location hosts share the brand as a prefix but differ in apex domain.
- WAF normalisation events that decode a redirect value differently from the application origin.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
