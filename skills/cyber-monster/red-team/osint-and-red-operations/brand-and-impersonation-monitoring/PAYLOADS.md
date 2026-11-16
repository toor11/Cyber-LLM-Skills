# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`brand-and-impersonation-monitoring`](SKILL.md) | Family: **OSINT and Red Operations**

Probes for `brand-and-impersonation-monitoring`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Candidate content differential

Baseline: the genuine site's login page fields. Probe: the candidate's corresponding fields. Differential: a content match with a different form action is active impersonation.

```bash
curl -sS https://target.example/login | grep -oE 'action="[^"]+"' | head -3
curl -sS https://target-secure-login.example/ | grep -oE 'action="[^"]+"' | head -3
```

## Certificate check for a candidate

Baseline: no certificate or a parked certificate. Probe: a certificate with a live subject. Differential: a valid certificate plus content means the site is being actively served.

```bash
echo | openssl s_client -connect target-secure-login.example:443 -servername target-secure-login.example 2>/dev/null | openssl x509 -noout -subject -issuer -dates
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
