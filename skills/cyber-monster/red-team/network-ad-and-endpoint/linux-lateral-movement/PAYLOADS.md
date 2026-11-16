# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`linux-lateral-movement`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `linux-lateral-movement`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Credential inventory

**Expected differential.** A private key with restrictive permissions and no passphrase proves usability; a passphrase-protected key needs the passphrase as well.

```bash
ls -l ~/.ssh/
ssh-keygen -y -f ~/.ssh/id_ed25519 >/dev/null && echo usable
```

## Authorisation scope

**Expected differential.** A `from=` or `command=` restriction in the target's `authorized_keys` bounds the key's reach; its absence leaves it unrestricted.

```bash
grep -r 'ssh-' /home/*/.ssh/authorized_keys 2>/dev/null | head
ssh -o BatchMode=yes -o ConnectTimeout=3 user@target 'id'
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
