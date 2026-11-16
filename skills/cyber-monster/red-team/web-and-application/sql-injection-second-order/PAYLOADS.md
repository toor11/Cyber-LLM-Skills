# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`sql-injection-second-order`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `sql-injection-second-order`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Connectivity marker (write then read)

**Expected differential:** a unique benign token stored at the write endpoint later appears in the second-path output, proving the paths connect without any grammar test

```text
name=probe_7f3a_marker
profile_note=probe_7f3a_marker
```

### Deferred boundary (triggered on read)

**Expected differential:** a stored value carrying a quote changes the deferred query only after the second path runs, reverting when that read binds the value

```text
name=o'brien_probe
name=obrien_probe
```

### Deferred boolean pair

**Expected differential:** two stored values differing only by a true versus false predicate change the second-read row set when triggered

```text
display=zz' AND '1'='1
display=zz' AND '1'='2
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
