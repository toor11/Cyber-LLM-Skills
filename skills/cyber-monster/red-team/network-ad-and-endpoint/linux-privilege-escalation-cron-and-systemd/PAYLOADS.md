# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`linux-privilege-escalation-cron-and-systemd`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `linux-privilege-escalation-cron-and-systemd`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Job and script ownership

**Expected differential.** A writable job file or script executed by a root schedule is the finding; root-owned files are not.

```bash
ls -l /etc/cron.d /etc/cron.daily /etc/cron.hourly 2>/dev/null
find /etc/cron* /var/spool/cron -writable -ls 2>/dev/null
```

## Unit file permissions

**Expected differential.** A writable unit file in a system location proves the unit can be replaced; a root-owned 0644 file does not.

```bash
find /etc/systemd/system /lib/systemd/system -writable -name '*.service' 2>/dev/null
systemctl list-timers --all --no-pager
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
