# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`host-persistence-scheduled-and-wmi-persistence`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `host-persistence-scheduled-and-wmi-persistence`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Task population and XML

**Expected differential.** A non-Microsoft task with a blank author and a live action is the candidate; a Microsoft task is not.

```bash
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | Select-Object TaskName,TaskPath,Author
Export-ScheduledTask -TaskName <name> | Select-String 'LogonType|Command|Arguments'
```

## WMI subscription triad

**Expected differential.** All three objects present proves a live subscription; a filter alone does not fire.

```bash
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
