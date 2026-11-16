# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`password-reset-and-account-recovery`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `password-reset-and-account-recovery`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Host header link poisoning

**Expected differential:** the generated reset link host follows the injected Host or forwarded-host value, where a fixed-base implementation ignores it

```text
Host: <assessor-controlled-host>
X-Forwarded-Host: <assessor-controlled-host>
```

### Token single-use and binding differential

**Expected differential:** the token is accepted on replay or against another account, where a bound single-use token is refused the second time

```text
POST /reset token=<token> as the first use
POST /reset token=<token> replayed after a successful reset
```

### User-enumeration response differential

**Expected differential:** the response for a known account differs in status, length, or timing from an unknown one, where a hardened flow is uniform

```text
email=known@app.example
email=absent@app.example
```

### OTP rate-limit probe

**Expected differential:** repeated recovery-code submissions within one window are all processed, where a rate limit would throttle or lock

```text
POST /recover/verify otp=000000 repeated within one window
POST /recover/verify otp=<valid-otp>
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
