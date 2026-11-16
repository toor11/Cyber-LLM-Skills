# Detection Signals and Blue-Team Handoff

> Sub-skill: [`web-recon-and-content-discovery-javascript-analysis`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Access-log requests for `.js.map` files from external clients on production hosts.
- Unauthenticated fetches of application JavaScript chunks immediately followed by requests to internal `/api/` routes named only in those chunks.
- Secret-scanner CI findings where `process.env` is referenced wholesale in a webpack or Vite config file.
- Egress requests to a token's service endpoint (for example `sts.amazonaws.com` or `api.stripe.com`) shortly after a bundle download.
- CDN logs showing repeated downloads of the same hashed chunk by a single non-browser User-Agent.
- Source-control commits adding `devtool: 'source-map'` to a production build configuration.
- A key string observed in a public bundle later appearing as the credential in an authenticated API request log.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
