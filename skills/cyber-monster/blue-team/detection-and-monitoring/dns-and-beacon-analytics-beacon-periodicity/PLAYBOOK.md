# Operational Triage and Response Playbook

> Sub-skill: [`dns-and-beacon-analytics-beacon-periodicity`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `dns-and-beacon-analytics-beacon-periodicity`. Paired offensive/mechanics reference: [`c2-implant-and-beaconing`](../../../red-team/network-ad-and-endpoint/c2-implant-and-beaconing/SKILL.md).

## Triggers

- A single host shows a highly regular connection interval to one destination that no other host contacts.
- A threat hunt asks whether a named sleep value appears anywhere in the estate's egress.
- A previously quiet host begins steady low-volume connections after a user opened a document.
- An analyst disputes a beacon alert and the resolution and normalisation behind it are unknown.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Ten or more intervals, period holds across the sweep, single-host destination, endpoint process is unsigned or unexpected | Confirmed Malicious / Gap | Preserve the series and the endpoint chain, scope other hosts for the destination, then isolate the host |
| Period holds but the destination is contacted by many hosts with the same cadence | Benign Baseline (Agent Heartbeat) | Identify the agent from the endpoint plane, exclude by process plus destination, and keep the interval rule for other destinations |
| Score high at one resolution only, collapses at neighbours | Benign Baseline (Binning Artefact) | Do not escalate; record the artefact and add the neighbouring-resolution requirement to the rule |
| Strong interval regularity with flat-random byte sizes | Lead (Padded Channel) | Treat size evidence as unavailable in the write-up; pivot on destination rarity and endpoint process |
| Fewer than ten intervals in the window | Inconclusive (Short Series) | Widen the window if the sleep is long; do not score a burst as a beacon |
| Cadence visible on connection records but the interval vanishes on resolver logs | Benign Baseline (Resolver Caching) | Use the connection plane as the evidence source and note the resolver's flattening in the report |
| Destination unreachable in the connection plane because egress is sampled | Inconclusive (Sampling Gap) | Size the sampling rate and state the missed-check-in probability before trusting any dispersion figure |

## Containment and Recovery

1. **Preserve before mutating:** export the raw connection series with timestamps and byte counts, plus the endpoint process chain; an isolated host stops producing the series that proves the cadence.
2. **Check the destination's peer group before blocking:** a block on a destination that other hosts reach on a different cadence is a partial outage; scope the block to the destination address and the isolated host where possible.
3. **Expect failover:** an implant with a domain front or a second stage will move to another destination; monitor for a new single-host series after containment rather than closing on the first block.
4. **Record the scoring parameters:** resolution, normalisation, and sleep band belong in the closure record so the next analyst can reproduce the score rather than re-derive it.
