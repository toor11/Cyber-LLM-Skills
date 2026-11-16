# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`active-directory-trust-and-forest-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `active-directory-trust-and-forest-abuse`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Trust attributes and direction

**Expected differential.** Quarantine disabled plus an inbound direction proves the SID-history path across that trust.

```bash
netdom trust corp.example /domain:partner.example /quarantine
Get-ADTrust -Filter * | Select-Object Name,Direction,ForestTransitive,SIDFilteringQuarantined
```

## Selective authentication ACEs

**Expected differential.** An `Allowed to Authenticate` ACE naming a foreign principal proves a reachable service; its absence proves the boundary holds.

```bash
Get-Acl 'AD:CN=FS01,OU=Servers,DC=corp,DC=example' | Select-Object -ExpandProperty Access |
  Where-Object IdentityReference -match 'partner'
netdom trust corp.example /domain:partner.example /verify
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
