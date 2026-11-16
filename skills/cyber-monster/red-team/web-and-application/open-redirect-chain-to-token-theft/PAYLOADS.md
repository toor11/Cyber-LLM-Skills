# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`open-redirect-chain-to-token-theft`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `open-redirect-chain-to-token-theft`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Registered-prefix path extension

**Expected differential:** a callback that extends the registered prefix and forwards onward carries the code to the assessor host, while the exact callback keeps it on-origin

```text
redirect_uri=https://app.example/callback/forward?to=<assessor-controlled-host>
redirect_uri=https://app.example/callback
```

### Authorization-code Referer leak

**Expected differential:** the code appears in the callback URL and leaks through the Referer on the next navigation, absent when state and code stay server-side

```text
response_type=code&redirect_uri=https://app.example/callback then observe the Referer downstream
response_type=code&state=<one-time-state>
```

### Implicit-token fragment exposure

**Expected differential:** an implicit flow returns the token in the fragment to a brand-prefixed attacker host, which never occurs under exact matching

```text
response_type=token&redirect_uri=https://app.example.<assessor-controlled-host>/
response_type=code&redirect_uri=https://app.example/callback
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
