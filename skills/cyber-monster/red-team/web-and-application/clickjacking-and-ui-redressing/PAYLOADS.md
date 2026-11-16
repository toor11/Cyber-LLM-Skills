# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`clickjacking-and-ui-redressing`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `clickjacking-and-ui-redressing`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Cross-origin framability check

**Expected differential:** the target renders inside a cross-origin iframe versus being blanked or refused when framing headers are honoured

```text
<iframe src="https://target.example/account/settings" width=800 height=600></iframe>
open DevTools and read whether the frame document actually loaded
```

### Framing-header inspection

**Expected differential:** the response carries no `frame-ancestors` and no `X-Frame-Options`, versus a hardened response that sends `frame-ancestors 'none'`

```text
curl -sI https://target.example/account/settings
read X-Frame-Options and the Content-Security-Policy frame-ancestors directive
```

### DoubleClickjacking gesture probe

**Expected differential:** a double-click sequence that swaps to a top-level target window reaches the control, versus a single gesture a confirmation gate would stop

```text
window.open('https://target.example/account/settings', '_blank')
measure whether the sensitive control activates on the second click after a focus swap
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
