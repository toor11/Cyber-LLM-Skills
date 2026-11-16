# Detection Signals and Blue-Team Handoff

> Sub-skill: [`subdomain-takeover-ns-and-service-takeover`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Registry or registrar notifications of expiry for a nameserver domain used in a delegation.
- DNS resolver logs showing SERVFAIL or REFUSED for a delegated label that previously answered.
- Parent-zone change records where an NS delegation remains after the delegated account was closed.
- Cloud audit logs recording elastic IP release without removal of the corresponding A record.
- Certificate Transparency issuance for a delegated label via DNS-01 that the organization did not initiate.
- Passive DNS showing the authoritative nameserver set for a label changing to a different operator.
- Mail-flow monitoring where MX for a label resolves to a newly registered service domain.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
