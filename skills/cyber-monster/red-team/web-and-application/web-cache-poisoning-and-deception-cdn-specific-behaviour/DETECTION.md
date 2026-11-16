# Detection Signals and Blue-Team Handoff

> Sub-skill: [`web-cache-poisoning-and-deception-cdn-specific-behaviour`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Edge logs where two distinct URL forms resolve to one cache key, visible as identical `Age` and `cf-cache-status: HIT`.
- Requests containing encoded slashes (`%2f`) or dot segments on a CDN-fronted path recorded at the edge.
- `x-served-by` or `x-amz-cf-id` values repeating across requests for URLs the origin treats as different resources.
- Query parameters present in the origin log but absent from the CDN cache-key configuration.
- A rise in cache-hit ratio on a route immediately after requests with unusual path normalisation.
- Surrogate-key or cache-tag headers appearing in client-facing responses.
- The origin receiving a normalised path that differs from the client-supplied path for the same edge request id.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
