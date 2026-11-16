# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`service-enumeration-database-and-remote-access`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `service-enumeration-database-and-remote-access`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## MSSQL encryption requirement

**Expected differential.** `ENCRYPT_OFF` in the pre-login reply proves plaintext logins are accepted; `ENCRYPT_ON` proves forced encryption.

```bash
nmap -p 1433 --script ms-sql-info 10.20.30.40
nmap -p 1433 --script ms-sql-ntlm-info 10.20.30.40
```

## RDP security negotiation

**Expected differential.** A reply without `PROTOCOL_HYBRID` proves NLA is not required, so the logon screen is reachable pre-authentication.

```bash
nmap -p 3389 --script rdp-ntlm-info 10.20.30.41
nmap -p 3389 --script rdp-enum-encryption 10.20.30.41
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
