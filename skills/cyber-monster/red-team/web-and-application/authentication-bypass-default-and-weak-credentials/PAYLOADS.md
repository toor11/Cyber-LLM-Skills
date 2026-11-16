# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`authentication-bypass-default-and-weak-credentials`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `authentication-bypass-default-and-weak-credentials`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Vendor default pair check (single attempt)

**Expected differential:** the documented pair issues a session while a random control pair is rejected, using one authorised attempt each to respect lockout

```text
username=admin&password=admin  single authorised attempt
username=admin&password=changeme  single documented-default attempt
username=admin&password=zzUnlikelyControl!42  random control attempt
```

### First-run setup reachability

**Expected differential:** the install wizard returns a usable provisioning page after deployment, versus a completed-state redirect once setup is locked

```text
GET /setup  expect a redirect once first-run is complete
GET /install/step1  probe for a still-open provisioning wizard
```

### Lockout-threshold observation (read only)

**Expected differential:** the response changes to a lockout or 429 after a few failures, or never does, confirming whether a rate limit exists without spraying

```text
observe status across three failed attempts on one account
compare lockout-banner appearance against a freshly created account
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
