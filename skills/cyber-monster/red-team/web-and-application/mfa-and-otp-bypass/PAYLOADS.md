# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`mfa-and-otp-bypass`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `mfa-and-otp-bypass`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Attempt-ceiling probe (no brute force of real secrets)

**Expected differential:** a controlled sequence of deliberately wrong codes against a tester-owned account never triggers a 429 or lockout, unlike a rate-limited endpoint

```text
POST /mfa/verify  code=000001 (attempt 1 of N, tester account)
POST /mfa/verify  code=000002 (attempt 2 of N, tester account)
POST /mfa/verify  code=000003 (watch for a 429 or lockout that never arrives)
```

### Single-use and normalisation probe

**Expected differential:** resubmitting the last valid code, or the same code with whitespace or leading zeros, is accepted again when it should be consumed

```text
code= 123456  (leading space, same code resent)
code=123456 then code=00123456 (zero-padded variant of a used code)
```

### Session-binding and credential-confusion probe

**Expected differential:** a factor issued for tester account A submitted against tester account B's pending session is accepted, proving the code is not bound to the identity

```text
account B pending session + account A current code
account B pending session + account B current code (control)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
