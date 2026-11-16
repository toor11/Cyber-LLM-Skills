# Detection Signals and Blue-Team Handoff

> Sub-skill: [`enterprise-appliance-n-day-mail-collaboration`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Asset data showing mail or collaboration platform builds inside a published CVE's affected range.
- Webmail or autodiscover access logs with requests routing to backend management paths.
- Exposure of management or license endpoints on internet-facing interfaces in perimeter scans.
- Deserialization-indicative payloads or large encoded blobs POSTed to a management or license servlet.
- CISA KEV matches for the deployed mail gateway or file-transfer product.
- Backend handler logs receiving front-end-originated requests that bypassed the webmail authentication tier.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
