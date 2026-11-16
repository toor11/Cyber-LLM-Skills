# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`reverse-shells-and-payload-delivery`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `reverse-shells-and-payload-delivery`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Process-and-network pair

**Expected differential.** An interpreter child with an outbound connection to an unsanctioned destination proves the channel; a sanctioned destination does not.

```bash
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=3} -MaxEvents 50
Get-NetTCPConnection -State Established | Select-Object LocalPort,RemoteAddress,OwningProcess
```

## Egress policy

**Expected differential.** A port-based allow rule proves the gap; a destination allowlist proves the control.

```bash
Get-NetFirewallRule -Direction Outbound -Enabled True -Action Allow | Select-Object DisplayName
netsh advfirewall firewall show rule name=all | Select-String 'RemoteIP'
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
