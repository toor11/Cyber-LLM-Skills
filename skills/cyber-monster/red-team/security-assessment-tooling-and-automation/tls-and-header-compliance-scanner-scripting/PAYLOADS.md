# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`tls-and-header-compliance-scanner-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `tls-and-header-compliance-scanner-scripting`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Per-version handshake

Baseline: a TLS 1.2 handshake that completes. Probe: the same attempt at TLS 1.0 and 1.1. Differential: a completing handshake at a version the policy forbids is the finding.

```bash
openssl s_client -connect target.example:443 -tls1_2 -servername target.example </dev/null | head -20
openssl s_client -connect target.example:443 -tls1 -servername target.example </dev/null | head -20
```

## Header stability pair

Baseline: the header set of the first response. Probe: the header set of the second. Differential: identical sets make the header claim reportable; a difference means an edge or cache is in play.

```bash
curl -sS -D- -o /dev/null https://target.example/ | sort
curl -sS -D- -o /dev/null https://target.example/ | sort
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
