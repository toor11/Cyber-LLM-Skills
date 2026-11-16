# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`active-directory-kerberos-attacks-ticket-abuse-and-forgery`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `active-directory-kerberos-attacks-ticket-abuse-and-forgery`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Cache inspection

**Expected differential.** A TGT in the cache with an encryption type the account should not use is the artefact; a normal cache with AES tickets is baseline.

```bash
klist -e -f
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 30 |
  Where-Object { $_.Message -match 'Logon Type:\s+9' }
```

## TGT issuance shape

**Expected differential.** A 4768 with `PreAuthType 2` and no interactive logon on the host proves a key-based TGT request.

```bash
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4768} -MaxEvents 50 |
  Select-String -Pattern 'PreAuthType|TicketEncryptionType'
netexec smb 10.20.30.50 -u lowpriv -H <ntlm-hash> --logon-type 9
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
