# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`linux-privilege-escalation`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `linux-privilege-escalation`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Artefact inventory

**Expected differential.** A setuid binary outside the distribution's documented list, or a sudo rule naming an interpreter, is the finding; a documented set is not.

```bash
find / -xdev -perm -4000 -type f 2>/dev/null | sort
getcap -r / 2>/dev/null
```

## Input influence

**Expected differential.** A writable file that a privileged binary or job reads is the actionable condition; a read-only one is not.

```bash
sudo -l
find /etc/cron* /var/spool/cron -writable 2>/dev/null
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
