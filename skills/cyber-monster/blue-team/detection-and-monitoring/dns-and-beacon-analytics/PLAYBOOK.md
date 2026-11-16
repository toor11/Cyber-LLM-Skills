# Operational Triage and Response Playbook

> Sub-skill: [`dns-and-beacon-analytics`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `dns-and-beacon-analytics`. Paired offensive/mechanics reference: [`c2-implant-and-beaconing`](../../../red-team/network-ad-and-endpoint/c2-implant-and-beaconing/SKILL.md).

## Triggers

- A host's DNS profile against one registrable domain departs from its own baseline on more than one feature.
- A resolver or flow sensor surfaces a destination whose name space looks algorithmic or tunnel-shaped.
- An endpoint agent reports an image issuing DNS queries that no other host's same image issues.
- A threat-intelligence feed names a domain pattern and the analyst needs to know whether the estate resolved it.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Name-level features, cadence deviation, and an issuing process with no prior contact all present | Confirmed Malicious / Gap | Preserve the resolver rows, endpoint events, and any capture; scope other hosts that contacted the domain before containing |
| Name features present, cadence normal, process is a browser | Benign Baseline (CDN or Telemetry) | Record the destination class, add a narrow exclusion on the tenant subdomain, and keep the cadence signal for a future channel |
| Cadence regular but name features ordinary and destination sanctioned | Benign Baseline (Agent Heartbeat) | Identify the agent from the endpoint plane, exclude by process plus domain, and record the exclusion's owner |
| Endpoint plane shows the querying image but the resolver has no row | Inconclusive (Plane Gap) | Check DoH configuration and local forwarders on that host; the resolver view does not describe this host |
| Host absent from the resolver entirely while the agent reports online | Inconclusive (Resolver Bypass) | Treat as a visibility gap with a named host list; do not report the host as clean |
| High unique-subdomain ratio explained by certificate-transparency or GUID telemetry paths | Benign Baseline (Legitimate Random Names) | Normalise to the registrable domain and exclude the specific parent where the provider allows tenant scoping |
| Domain resolved by many hosts with identical low volume | Lead (Shared Infrastructure) | Enrich the destination and look for the same pattern across the estate before attributing any single host |

## Containment and Recovery

1. **Preserve before mutating:** capture the resolver rows, the endpoint event chain, and a pcap if the channel is active; once a domain is blocked, the host stops producing the evidence that would have scoped it.
2. **Scope the domain before blocking it:** resolve which hosts and business functions use the registrable domain, since a shared CDN parent can carry legitimate traffic and a fleet-wide block is an outage.
3. **Contain at the host and process:** isolate the host or terminate the specific image rather than blocking the resolver globally, and confirm the implant does not simply fail over to a second name.
4. **Close the visibility gaps named in the finding:** DoH bypasses and missing endpoint DNS events are permanent blind spots until they are onboarded, and they belong to the incident record rather than to a backlog.
