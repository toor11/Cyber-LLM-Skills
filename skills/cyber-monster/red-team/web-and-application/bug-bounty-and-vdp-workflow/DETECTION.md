# Detection Signals and Blue-Team Handoff

> Sub-skill: [`bug-bounty-and-vdp-workflow`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Web access logs where the programme's required identification header such as X-Bug-Bounty is present on a session.
- Traffic to hosts outside the programme's structured-scopes list from a known researcher source IP.
- A single source systematically probing many subdomains under the programme wildcard.
- Requests to explicitly out-of-scope assets such as marketing subdomains flagged against the scope allowlist.
- Candidate findings whose signature matches an already-resolved report fingerprint in the tracker.
- Bursts of low-impact, self-scoped actions that never cross into a second test account.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
