# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`bug-bounty-and-vdp-workflow`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `bug-bounty-and-vdp-workflow`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Scope membership check

**Expected differential:** a candidate host matches the normalised allowlist while a look-alike is rejected, proving the boundary before any probing

```text
check api.example.com against the programme scope allowlist
check example.com.evil.test against the programme scope allowlist
```

### Duplicate-cluster check (read only)

**Expected differential:** the candidate finding matches an already-resolved report signature, versus a novel endpoint and parameter pairing

```text
search disclosed reports for the same endpoint and parameter
compare the root-cause signature against resolved programme reports
```

### Cross-account impact confirmation

**Expected differential:** the effect reaches a second test account rather than only the researcher's own session, proving cross-boundary impact

```text
reproduce the action from test-account-B against test-account-A
confirm the state change persists on the victim test account
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
