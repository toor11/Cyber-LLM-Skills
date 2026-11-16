# Detection Queries and Telemetry Artifacts

> Sub-skill: [`cti-collection-and-enrichment`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Pipeline hygiene checks. Each row names the field and the state a healthy store shows.

## Provenance

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Source record | records with at least one named source and retrieval date | 100% |
| First seen | earliest `first_seen` across sources | Present and used for decay |
| Signature or auth | feeds authenticated or signed | All production feeds |

## Deduplication

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Observable duplicates | records sharing a value but differing in campaign | Preserved as separate relationships |
| Exact duplicates | identical value plus identical context | Collapsed with merged source list |
| Reseller chains | same indicator from feeds that resell one upstream | Upstream counted once for corroboration |

## Enrichment

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Internal observation | `observed_in_estate.hits` per record | Present, including zero |
| Infrastructure context | ASN, hosting type, shared-hosting flag | Present for network indicators |
| Action recommendation | `recommended_action` with rationale | Present; block only when the rationale supports it |

## Telemetry Prerequisites

- A structured store (STIX 2.1 compatible or equivalent) with relationship support.
- Query access to telemetry for the observation join, since that is what makes enrichment real.
- A source register naming upstreams, so reseller chains are not counted as independent corroboration.

## Deployment Gates

- No indicator enters the store without a source and a first-seen date.
- Block recommendations require an infrastructure rationale; shared hosting defaults to hunt.
