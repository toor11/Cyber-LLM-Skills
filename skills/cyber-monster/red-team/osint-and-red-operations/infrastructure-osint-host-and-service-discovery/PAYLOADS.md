# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`infrastructure-osint-host-and-service-discovery`](SKILL.md) | Family: **OSINT and Red Operations**

Probes for `infrastructure-osint-host-and-service-discovery`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Prefix-scoped query with fields

Baseline: the announced prefix list. Probe: dataset records inside those prefixes. Differential: records outside the prefixes are excluded regardless of content match.

```bash
curl -sS 'https://api.example/shodan/host/search?key=KEY&query=net:198.51.100.0/24&fields=ip_str,port,product,version,timestamp'
curl -sS 'https://api.example/shodan/host/search?key=KEY&query=net:198.51.100.0/24&minify=false&fields=ip_str,port,http.title,timestamp'
```

## Scan-date freshness filter

Baseline: all records for a host. Probe: records within the freshness window. Differential: a service present only in old records needs a current confirmation.

```bash
jq '[.matches[] | select(.timestamp > "2026-08-01")] | length' out.json
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
