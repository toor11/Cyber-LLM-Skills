# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`infrastructure-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Probes for `infrastructure-osint`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Registration to routing chain

Baseline: the registrant handle. Probe: the announced prefixes for the associated ASN. Differential: addresses inside the prefixes are attributable; those outside need separate corroboration.

```bash
curl -sS https://rdap.example/domain/target.example | jq '.entities[].handle'
whois -h whois.radb.net -- '-i origin AS64500' | head -20
```

## Certificate-name harvest

Baseline: names known from DNS. Probe: names from certificate transparency. Differential: a name present only in CT is a candidate asset needing confirmation.

```bash
curl -sS 'https://crt.sh/?q=%25.target.example&output=json' | jq -r '.[].name_value' | sort -u
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
