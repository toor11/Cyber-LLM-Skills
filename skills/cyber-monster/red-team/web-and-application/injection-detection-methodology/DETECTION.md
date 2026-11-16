# Detection Signals and Blue-Team Handoff

> Sub-skill: [`injection-detection-methodology`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Access logs where one parameter cycles through structurally different values (quotes, angle brackets, arithmetic) from one session within seconds.
- Application error events whose message text contains a boundary character that originated from a request parameter.
- Response-length or status distributions for a single route shifting between two logically opposite parameter values.
- Query-latency distribution shifts on one route while request volume stays flat, characteristic of timing probes.
- Outbound DNS or HTTP connections from the app host to an unfamiliar domain shortly after a crafted parameter value.
- Parameter-mining tooling user-agents (Arjun, ParamMiner) preceding bursts of single-character probe requests.
- WAF rule hits for injection boundary characters followed by a 200 from the origin on the same route.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
