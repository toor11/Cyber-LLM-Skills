# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`pivoting-and-tunneling`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `pivoting-and-tunneling`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Foothold reachability

**Expected differential.** A target reachable from the foothold but not from the assessment host proves the pivot's premise; equal reach proves it adds nothing.

```bash
ssh user@foothold 'ip route show; nc -zv 10.20.40.15 1433'
nc -zv 10.20.40.15 1433
```

## Egress state

**Expected differential.** An unrestricted default route proves the foothold has both reach and egress; a restrictive ACL proves it does not.

```bash
ssh user@foothold 'curl -sS -o /dev/null -w "%{http_code}" https://example.com --max-time 5'
ssh user@foothold 'ss -tunp | head -20'
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
