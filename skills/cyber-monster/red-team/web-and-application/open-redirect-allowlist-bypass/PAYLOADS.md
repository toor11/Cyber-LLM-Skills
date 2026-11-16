# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`open-redirect-allowlist-bypass`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `open-redirect-allowlist-bypass`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Suffix and substring allowlist probe

**Expected differential:** a brand-prefixed subdomain or path-embedded brand passes the loose comparison while a plainly foreign host is rejected

```text
redirect=https://target.example.<assessor-controlled-host>/
redirect=https://nottarget.example/
```

### Userinfo authority confusion

**Expected differential:** an @-authority form routes to the attacker host while appearing to reference the trusted brand before the @

```text
redirect=https://target.example@<assessor-controlled-host>/
redirect=https://<assessor-controlled-host>#@target.example/
```

### Encoded-value revalidation gap

**Expected differential:** a percent-encoded authority passes a validator that runs before decoding, then resolves to the foreign host after decode

```text
redirect=https:%2f%2f<assessor-controlled-host>/
redirect=%2f%2f<assessor-controlled-host>
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
