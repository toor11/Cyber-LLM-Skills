# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`csp-and-security-header-bypass`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `csp-and-security-header-bypass`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Policy capture and enforcement baseline

**Expected differential:** the served CSP text lists the directives in play, and a benign no-nonce inline script triggers a violation report, proving enforcement is live

```text
curl -sI https://target.example/app | grep -i content-security-policy
<script>void('zzcsp-baseline')</script>  (no nonce: should be blocked and reported)
```

### Nonce reuse check

**Expected differential:** two fetches of the same route return the same nonce value versus a fresh value each time

```text
curl -s https://target.example/app | grep -o 'nonce-[A-Za-z0-9_-]*'  (fetch 1)
curl -s https://target.example/app | grep -o 'nonce-[A-Za-z0-9_-]*'  (fetch 2, compare)
```

### Missing-directive gadget probe

**Expected differential:** a construct the policy forgot to restrict is permitted, versus being blocked once the directive is set

```text
<base href="https://<assessor-controlled-host>/">  (tests absent base-uri)
<form action="https://<assessor-controlled-host>/collect" method=post>  (tests absent form-action)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
