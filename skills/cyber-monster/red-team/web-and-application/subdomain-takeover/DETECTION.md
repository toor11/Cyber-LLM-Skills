# Detection Signals and Blue-Team Handoff

> Sub-skill: [`subdomain-takeover`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Passive DNS feeds showing a CNAME for a company label whose target resolution changed owner.
- Certificate Transparency log entries issuing a certificate for a subdomain the organization did not request.
- External scanner results flagging provider fingerprints such as `NoSuchBucket` or a Pages 404 on the organization labels.
- Zone-file diffs in the DNS management system where a service-account deletion is not paired with a record deletion.
- HTTP monitoring where a subdomain response body changes from owned content to a provider default page.
- Cloud audit logs recording release of an elastic IP or bucket while the corresponding DNS record remains in the zone.
- Registrar or DNS provider API logs showing NS delegation changes for a label no longer in active use.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
