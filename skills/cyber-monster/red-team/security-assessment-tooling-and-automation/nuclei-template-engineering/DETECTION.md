# Detection Signals and Blue-Team Handoff

> Sub-skill: [`nuclei-template-engineering`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Web logs showing the Nuclei default user-agent or a template id in a header, correlated with a burst of paths.
- Sequential requests for advisory-specific paths (`/actuator/env`, `/.git/config`) from one source address.
- A high 404 ratio on one host within seconds, characteristic of template path iteration.
- `nuclei` process names in EDR inventory on hosts that should not run scanners.
- Requests with `max-redirects` behaviour: a 302 that is never followed, unlike a browser.
- JSONL output files written to a shared path, indicating scan results stored outside the engagement workspace.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`waf-and-modsecurity-crs-rule-engineering`](../../../blue-team/security-automation-and-tool-development/waf-and-modsecurity-crs-rule-engineering/SKILL.md) | Query authoring, triage, and hardening |
