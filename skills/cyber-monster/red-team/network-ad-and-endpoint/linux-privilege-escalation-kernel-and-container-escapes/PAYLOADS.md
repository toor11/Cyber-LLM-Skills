# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`linux-privilege-escalation-kernel-and-container-escapes`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `linux-privilege-escalation-kernel-and-container-escapes`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Kernel identity

**Expected differential.** The package version plus changelog proves whether a named fix is present; the version string alone does not.

```bash
uname -a
dpkg -l 'linux-image*' 2>/dev/null | tail -5 || rpm -q kernel
```

## Container configuration

**Expected differential.** A socket, a privileged flag or a broad capability set proves an escape path; a read-only non-root container with dropped capabilities does not.

```bash
grep -E 'CapEff|CapBnd' /proc/self/status
cat /proc/self/mountinfo | grep -E 'docker.sock|/host|/var/run'
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
