# Detection Signals and Blue-Team Handoff

> Sub-skill: [`headless-browser-dom-security-audit-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- User-agent strings containing `HeadlessChrome` in web access logs for a site that expects real browsers.
- Browser binaries launched from a server process tree with `--headless=new` and no display variable.
- `securitypolicyviolation` reports arriving from a client that also fetches many pages in seconds.
- WebDriver or CDP endpoints (`/json/version`, `/session`) exposed on a host that should not run automation.
- A single client requesting the same page repeatedly with one query parameter varying.
- Playwright or Puppeteer driver processes in EDR inventory on non-testing hosts.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) | Query authoring, triage, and hardening |
