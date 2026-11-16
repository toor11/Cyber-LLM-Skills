# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`linux-privilege-escalation-nfs-and-share-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `linux-privilege-escalation-nfs-and-share-abuse`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Export and option inventory

**Expected differential.** `no_root_squash` on a writable export is the finding; `root_squash` narrows it considerably.

```bash
showmount -e 10.20.30.40
cat /etc/exports 2>/dev/null || exportfs -v
```

## Ownership behaviour

**Expected differential.** A file created as root appearing as `nobody` on the server proves squash is working; appearing as root proves it is not.

```bash
touch /mnt/export/ownership-test && ls -ln /mnt/export/ownership-test
stat -c '%U:%G %a' /mnt/export/ownership-test
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
