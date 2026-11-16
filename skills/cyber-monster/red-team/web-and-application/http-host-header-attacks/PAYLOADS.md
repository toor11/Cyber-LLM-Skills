# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`http-host-header-attacks`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `http-host-header-attacks`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Host reflection into a generated link

**Expected differential:** the attacker host appears in a generated link or redirect versus a configured host that stays constant

```text
X-Forwarded-Host: <assessor-controlled-host> on a reset-link request
Host: <assessor-controlled-host> on the same reset-link request
```

### Forwarded-host routing

**Expected differential:** a forwarded host reaches a different backend or virtual host versus one pinned to Host

```text
X-Forwarded-Host: internal-vhost.<assessor-controlled-host>
Forwarded: host=<assessor-controlled-host> on the same route
```

### Host in cache key

**Expected differential:** a poisoned host reflected into a cacheable response is retrievable by a second client versus keyed out

```text
send Host: <assessor-controlled-host> to a cacheable path, then re-request as a victim
compare the second client body against the legitimate-host baseline
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
