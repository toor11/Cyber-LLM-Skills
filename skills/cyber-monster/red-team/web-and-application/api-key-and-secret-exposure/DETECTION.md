# Detection Signals and Blue-Team Handoff

> Sub-skill: [`api-key-and-secret-exposure`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- CloudTrail events where an AKIA access key is used from an IP or ASN outside the application's known egress ranges.
- Provider dashboard alerts for an sk_live_ key making calls from a new user-agent or geography.
- GitHub secret-scanning push-protection alerts naming the repository and the detected secret type.
- CDN or web access logs serving a .js.map source map that production should not publish.
- Scanner findings mapping a committed secret to a specific commit hash and author in history.
- A surge of 401 or 403 from a provider API shortly after a key appears in a public paste or bundle.
- WAF response-body logs where content returned to the browser contains an AIza or ghp_ token pattern.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
