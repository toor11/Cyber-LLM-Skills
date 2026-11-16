# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`host-persistence-linux-and-macos-persistence`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `host-persistence-linux-and-macos-persistence`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Provenance check

**Expected differential.** A unit or plist with no package owner proves an addition outside management; a package-owned one is expected.

```bash
systemctl list-unit-files --state=enabled
dpkg -S /etc/systemd/system/*.service 2>/dev/null | head
```

## Loaded path permission

**Expected differential.** A group- or world-writable script loaded by a privileged entry is the finding; a root-owned 0755 script is not.

```bash
grep -R 'ExecStart' /etc/systemd/system/*.service | head
ls -l /etc/ld.so.preload ~/Library/LaunchAgents 2>/dev/null
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
