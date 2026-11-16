# Detection Signals and Blue-Team Handoff

> Sub-skill: [`web-fingerprinting-and-tech-detection`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Access logs showing one client requesting `/favicon.ico`, `/robots.txt`, and multiple default asset paths in rapid succession.
- User-Agent strings matching whatweb, httpx, Wappalyzer, or nuclei in the web server log.
- A burst of requests that each trigger 404 or 400 error templates from one source.
- Requests for product-default paths (`/wp-login.php`, `/administrator/`, `/actuator`) from a single IP.
- Malformed HTTP version or method requests crafted to elicit server error pages.
- Repeated HEAD requests reading only response headers across many paths.
- Favicon requests correlated with subsequent targeted requests to version-specific endpoints.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
