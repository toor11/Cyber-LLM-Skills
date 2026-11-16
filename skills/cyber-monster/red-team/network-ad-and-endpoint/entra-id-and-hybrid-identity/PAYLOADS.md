# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`entra-id-and-hybrid-identity`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `entra-id-and-hybrid-identity`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Authentication method and sync principal

**Expected differential.** A federated or PHS configuration with a broad-roled sync app proves a large bridge; a narrow sync role does not.

```bash
Get-MgDomain | Select-Object Id,AuthenticationType,IsVerified
Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Entra Connect Sync'" | Select-Object Id,AppId,KeyCredentials
```

## Device trust write path

**Expected differential.** A write ACE on `userCertificate` for a non-tier-0 principal proves device impersonation is possible.

```bash
Get-Acl 'AD:CN=PAW01,OU=Devices,DC=corp,DC=example' | Select-Object -ExpandProperty Access
Get-ADComputer PAW01 -Properties userCertificate
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
