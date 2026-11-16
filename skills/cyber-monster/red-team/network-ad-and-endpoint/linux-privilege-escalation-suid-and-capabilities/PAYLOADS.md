# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`linux-privilege-escalation-suid-and-capabilities`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `linux-privilege-escalation-suid-and-capabilities`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Inventory and package accounting

**Expected differential.** A setuid file unaccounted for by any package proves an added artefact; a package-owned one is expected.

```bash
find / -xdev -perm -4000 -type f 2>/dev/null
dpkg -S /usr/local/bin/backupctl 2>/dev/null || rpm -qf /usr/local/bin/backupctl 2>/dev/null
```

## Input influence

**Expected differential.** A writable library path or config used by a privileged binary is the actionable condition; a root-owned read-only one is not.

```bash
readelf -d /usr/local/bin/backupctl | grep -i 'rpath\|runpath'
getcap -r / 2>/dev/null | grep -E 'cap_setuid|cap_dac'
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
