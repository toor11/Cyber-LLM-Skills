# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`linux-privilege-escalation-sudo-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `linux-privilege-escalation-sudo-abuse`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Effective rule set

**Expected differential.** A rule granting an interpreter proves unrestricted execution; a wrapper-granting rule does not.

```bash
sudo -l
sudo -ll | sed -n '1,80p'
```

## Environment preservation

**Expected differential.** An `env_keep` entry for a loader variable proves code injection into the permitted binary.

```bash
sudo -ll | grep -i env_keep
grep -r 'env_keep' /etc/sudoers /etc/sudoers.d 2>/dev/null
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
