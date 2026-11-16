# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`pivoting-and-tunneling-socks-and-port-forwarding`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `pivoting-and-tunneling-socks-and-port-forwarding`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Forwarding permission

**Expected differential.** `allowtcpforwarding yes` proves the capability is available; `no` proves it is not.

```bash
sshd -T | Select-String 'allowtcpforwarding|permitopen'
ssh -o ExitOnForwardFailure=yes -N -L 1433:10.20.40.15:1433 user@foothold
```

## Apparent source

**Expected differential.** The target's log naming the foothold address proves traversal; the assessment host's address proves a direct connection.

```bash
ssh user@foothold 'ss -tn state established | head'
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 20 | Select-String 'Source Network Address'
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
