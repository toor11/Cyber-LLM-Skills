# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`active-directory-enumeration-gpo-and-administrative-discovery`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `active-directory-enumeration-gpo-and-administrative-discovery`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Linkage and edit rights

**Expected differential.** An ACE naming a non-tier-0 trustee on a GPO whose link covers Tier-0 objects is the finding; the same ACE on an unlinked GPO is not.

```bash
Get-GPO -All | Select-Object DisplayName,Id,GpoStatus
netexec ldap 10.20.30.10 -u lowpriv -p pass --query '(objectClass=groupPolicyContainer)' displayName,gPCFileSysPath
```

## Stored credential state

**Expected differential.** A `cpassword` attribute in a SYSVOL XML file proves a recoverable credential is published to every authenticated principal.

```bash
find /mnt/sysvol -name Groups.xml -exec grep -l cpassword {} \;
Get-ChildItem -Recurse '\\corp.example\SYSVOL\corp.example\Policies' -Filter *.xml | Select-String cpassword
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
