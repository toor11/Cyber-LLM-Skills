# Detection Signals and Blue-Team Handoff

> Sub-skill: [`dns-rebinding-attacks`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Recursive DNS logs showing a name with an unusually low TTL answered first with an external then an internal or RFC1918 address.
- Local service access logs where the `Host` header is an external domain rather than localhost or the service's own name.
- Browser-subnet DNS queries repeatedly re-resolving the same short-TTL hostname within seconds.
- Internal service responses to requests whose `Origin` or `Referer` points to an unrelated external site.
- Firewall or flow logs showing a browser host connecting to 127.0.0.1 or an RFC1918 service immediately after an external DNS lookup.
- Desktop-agent logs accepting requests without an authentication token from a browser-originated connection.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
