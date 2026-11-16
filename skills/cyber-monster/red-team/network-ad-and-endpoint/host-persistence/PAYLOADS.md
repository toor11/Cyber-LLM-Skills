# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`host-persistence`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `host-persistence`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Autostart population

**Expected differential.** An entry with no package or signature provenance and a live target is the candidate; a signed vendor entry is not.

```bash
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
systemctl list-unit-files --state=enabled --type=service --no-legend
```

## Surface authorisation

**Expected differential.** A write ACE for a broad group on a machine-wide autostart surface proves any user can persist; a restricted ACL does not.

```bash
Get-Acl 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
ls -l /etc/systemd/system /etc/cron.d
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
