# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`csrf`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `csrf`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Cross-site form submission (no script)

**Expected differential:** the victim's stored value changes after the foreign page loads, while the same form served from the target origin also changes it; a rejection or unchanged value means a control fired

```text
<form method="POST" action="https://target.example/account/email"><input name="email" value="assessor@example.org"></form><script>document.forms[0].submit()</script>
<form method="POST" action="https://target.example/account/email" enctype="text/plain"><input name='email"value="assessor@example.org"x' value=""></form>
```

### Token enforcement probes

**Expected differential:** removing the token, or reusing it after rotation, is rejected with 403; acceptance proves the server is not comparing it

```text
POST /account/email HTTP/1.1  (token header removed, cookie only)
POST /account/email HTTP/1.1  (token from a previous session, current cookie)
```

### Cookie attribute inspection

**Expected differential:** the Set-Cookie line shows `SameSite=None` or no attribute at all, which makes the ambient credential available to cross-site requests

```text
Set-Cookie: session=<value>; Path=/; HttpOnly
Set-Cookie: session=<value>; Path=/; HttpOnly; SameSite=None
```

### Secondary-check bypass

**Expected differential:** a foreign Origin is accepted because the comparison is a suffix or substring match, so the request proceeds while a genuinely foreign origin string is rejected

```text
Origin: https://target.example.assessor.test
Origin: https://assessor-target.example
```

### Content-type and method assumption

**Expected differential:** a body sent as `text/plain` or `application/x-www-form-urlencoded` is parsed by the handler, which removes the preflight protection the JSON assumption relied on

```text
Content-Type: text/plain
Content-Type: application/x-www-form-urlencoded
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
