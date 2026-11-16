# Detection Signals and Blue-Team Handoff

> Sub-skill: [`subdomain-takeover-cname-fingerprints`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Certificate Transparency entries for a subdomain CNAME'd to a provider the organization did not authorize.
- External monitoring where a CNAME'd subdomain body matches a provider unclaimed-resource signature.
- DNS management exports listing CNAME targets at providers such as `github.io` or `s3.amazonaws.com` with no active owning account.
- CDN or provider billing showing a resource deleted while DNS still publishes its CNAME.
- Scanner output from subjack or nuclei takeover templates flagging provider fingerprints on company labels.
- HTTP response-body change monitoring on marketing or docs subdomains from live content to a provider 404.
- Passive DNS showing a CNAME target host whose IP set changed to a provider default edge.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
