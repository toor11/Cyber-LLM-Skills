# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`web-archival-and-deleted-content-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Probes for `web-archival-and-deleted-content-osint`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Capture chronology

Baseline: an empty CDX result indicating no capture. Probe: a capture list with digests. Differential: a digest change between captures brackets the content edit.

```bash
curl -sS 'https://web.archive.org/cdx/search/cdx?url=target.example/pricing&output=json&from=2023&to=2023'
curl -sS 'https://web.archive.org/cdx/search/cdx?url=target.example/pricing&output=json&collapse=digest'
```

## Crawl index cross-check

Baseline: the archive capture list. Probe: the crawl index for the same URL. Differential: a crawl record with a date the archive lacks is new evidence, not a duplicate.

```bash
curl -sS 'https://index.commoncrawl.org/CC-MAIN-2026-30-index?url=target.example%2Fpricing&output=json'
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
