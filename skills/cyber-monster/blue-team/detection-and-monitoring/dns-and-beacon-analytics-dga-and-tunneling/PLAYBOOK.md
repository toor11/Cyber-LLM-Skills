# Operational Triage and Response Playbook

> Sub-skill: [`dns-and-beacon-analytics-dga-and-tunneling`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `dns-and-beacon-analytics-dga-and-tunneling`. Paired offensive/mechanics reference: [`c2-implant-and-beaconing`](../../../red-team/network-ad-and-endpoint/c2-implant-and-beaconing/SKILL.md).

## Triggers

- A parent domain shows a unique-subdomain ratio near one with long leftmost labels from a small number of hosts.
- A host generates a large volume of NXDOMAIN responses under one parent domain.
- A parent domain carries TXT or NULL queries at a volume no business process explains.
- A threat-intelligence report names a tunnelling tool and the analyst must determine whether the estate carries its shape.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Unique-subdomain ratio, label length, byte-per-query growth, and fleet rarity all present, with an unexpected issuing process | Confirmed Malicious / Gap | Preserve the query set and endpoint chain, scope other hosts for the parent, then sinkhole or block the parent with the blast radius recorded |
| Same shape but the parent is contacted by most of the fleet with uniform volume | Benign Baseline (CDN or Vendor Infrastructure) | Record the parent in the sanctioned list at the tenant subdomain level and document why name statistics are uninformative here |
| NXDOMAIN share high but candidate names are dictionary words | Benign Baseline (Search Suffix Misconfiguration) | Fix the client's suffix configuration; no security finding, but record the client as a source of future noise |
| TXT volume high on a mail or certificate parent | Benign Baseline (SPF, DKIM, ACME) | Exclude the specific parent; do not lower the record-type threshold globally |
| Parent rarity and label profile present but no endpoint plane row | Inconclusive (Attribution Gap) | Report the domain as a lead with the missing attribution named, and onboard endpoint DNS events for that host segment |
| Byte correlation computed only on resolver logs | Inconclusive (Caching Distortion) | Recompute on egress or endpoint records; the resolver's cached answers do not describe the host's request pattern |
| Parent is a public suffix shared across tenants | Inconclusive (Unattributable Name Space) | Enrich to the tenant subdomain level before any block; a parent-level block is an outage risk |

## Containment and Recovery

1. **Preserve before mutating:** capture the query set for the parent, the answer sizes, and the endpoint process chain; a sinkhole replaces the answers and destroys the comparison baseline.
2. **Sinkhole or block at the narrowest useful scope:** prefer a resolver policy scoped to the parent's tenant subdomain over a registrable-domain block, and record which hosts were reaching it before the change.
3. **Look for the alternate channel:** a tunnelling implant commonly has a fallback domain; monitor for a new single-host parent after containment rather than closing on the first block.
4. **Feed enrichment gaps back:** where registration age or hosting could not be obtained, record the missing source so the next investigation does not stall at the same point.
