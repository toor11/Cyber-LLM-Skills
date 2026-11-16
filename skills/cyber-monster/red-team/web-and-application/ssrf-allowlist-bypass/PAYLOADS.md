# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`ssrf-allowlist-bypass`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `ssrf-allowlist-bypass`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Outward baseline (server-origin proof)

**Expected differential:** the callback arrives from the server egress with the server client User-Agent, not the browser

```text
url=https://<assessor-controlled-host>/allowlist-baseline
```

### Validator-versus-resolver disagreement

**Expected differential:** an allowed name that resolves inward succeeds while the literal inward host is rejected

```text
url=https://<allowed-name-resolving-inward>/
url=http://<internal-host>/status
```

### Encoded address forms

**Expected differential:** an encoded inward literal reaches the same service as the dotted form, proving differing normalisation

```text
url=http://2130706433/
url=http://[::ffff:127.0.0.1]/
```

### Redirect and userinfo tricks

**Expected differential:** an allowed host that 302s inward, or a user@internal authority, points the real connection inward

```text
url=https://<allowed-host>/redirect?to=<internal-host>
url=https://<allowed-host>@<internal-host>/
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
