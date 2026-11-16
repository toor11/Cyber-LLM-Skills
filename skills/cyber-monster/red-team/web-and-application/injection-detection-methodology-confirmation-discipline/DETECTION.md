# Detection Signals and Blue-Team Handoff

> Sub-skill: [`injection-detection-methodology-confirmation-discipline`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Assessment logs showing a single probe value reported as a finding without any paired control or repeat request.
- Repeated identical benign requests in the same session whose recorded response sizes differ, indicating an unmeasured noise band.
- Probe requests whose effect is absent once a unique cache-buster query value is added.
- Timing-based findings backed by one sample rather than a distribution across repeats.
- Candidate findings where no escaped-probe control request appears in the request history.
- Differentials recorded only on batched request groups and never on interleaved single requests.
- Finding records lacking a documented revert, where the structural character was never neutralised to retest.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
