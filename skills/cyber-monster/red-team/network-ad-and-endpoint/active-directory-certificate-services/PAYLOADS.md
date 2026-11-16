# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`active-directory-certificate-services`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `active-directory-certificate-services`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## CA and template inventory

**Expected differential.** The published set and the CA endpoint prove what is reachable; an unpublishable template is out of scope.

```bash
certipy find -u lowpriv@corp.example -p pass -dc-ip 10.20.30.10 -vulnerable -stdout
certutil -CAInfo
```

## CA-wide overrides

**Expected differential.** A SID extension in the disable list proves ESC16 for the whole CA; a v1 template on an unpatched CA proves ESC15.

```bash
certutil -getreg policy\DisableExtensionList
Get-ADObject -SearchBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp' -Filter {msPKI-Template-Schema-Version -le 1}
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
