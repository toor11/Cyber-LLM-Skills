# Detection Signals and Blue-Team Handoff

> Sub-skill: [`cross-site-scripting-reflected`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Web access logs where a query or path parameter value contains angle brackets or a quote and the same value drives the response body size on that route.
- WAF XSS signature hits (for example ModSecurity 941xxx) on a GET parameter immediately followed by a 200 from origin on the same path.
- Response bodies on a search or error route whose length grows by the length of a reflected parameter containing tag characters.
- CSP `report-uri` or `report-to` violation reports citing inline `script-src` on a route that reflects input.
- Repeated requests from one session to a single route alternating a benign marker and an angle-bracket variant within seconds.
- `Referer` or `User-Agent` header values reflected into an error page, captured where those headers carry script metacharacters.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
