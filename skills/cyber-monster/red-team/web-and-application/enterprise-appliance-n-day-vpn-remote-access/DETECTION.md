# Detection Signals and Blue-Team Handoff

> Sub-skill: [`enterprise-appliance-n-day-vpn-remote-access`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Appliance access logs showing requests to pre-auth portal paths (`/remote/login`, locale or diagnostic CGIs) from scanner User-Agents.
- VPN gateway logs with HTTP 200 on language-file or template endpoints whose parameter contains `../` sequences.
- Repeated requests to one pre-auth endpoint from a single source across many firmware-specific URL variants, consistent with version enumeration.
- Outbound connections from the appliance management interface to untrusted hosts shortly after a pre-auth request burst.
- Known-scanner nuclei template signatures recorded by the WAF fronting the gateway.
- New local accounts or session tokens on the appliance created without a preceding successful credential event.
- TLS SNI values probing multiple virtual hosts on the gateway address within one session.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
