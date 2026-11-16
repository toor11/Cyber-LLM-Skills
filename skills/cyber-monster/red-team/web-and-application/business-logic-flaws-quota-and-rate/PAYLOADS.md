# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`business-logic-flaws-quota-and-rate`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `business-logic-flaws-quota-and-rate`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Serial-versus-burst count

**Expected differential:** serial requests stop at the ceiling while a synchronized burst grants more; read the server-side granted count, do not exhaust shared resources

```text
send N requests one after another, read granted count
release N identical requests together, read granted count
```

### Counter-key multiplication

**Expected differential:** varying a normalised-equivalent key restarts the counter versus repeating the same key

```text
key=user+tag@example.test  (alias form, read quota)
key=user@example.test  (canonical form, read quota)
```

### Window-reset probe

**Expected differential:** a client-supplied window or reset timestamp renews the allowance versus omitting it

```text
window_start=now  (baseline, read remaining)
window_start=0  (forced reset, read remaining)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
