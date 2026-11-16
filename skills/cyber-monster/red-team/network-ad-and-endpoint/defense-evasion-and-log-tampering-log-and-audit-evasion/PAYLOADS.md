# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`defense-evasion-and-log-tampering-log-and-audit-evasion`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `defense-evasion-and-log-tampering-log-and-audit-evasion`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Effective policy

**Expected differential.** A disabled policy-change subcategory proves weakening will go unrecorded; enabled proves it will be recorded.

```bash
auditpol /get /category:*
auditpol /get /subcategory:'Audit Policy Change'
```

## Object SACL state

**Expected differential.** A SACL missing on the directory service object proves directory events are not generated; a present SACL proves they are.

```bash
(Get-Acl 'AD:DC=corp,DC=example').Audit
wevtutil gl Security
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
