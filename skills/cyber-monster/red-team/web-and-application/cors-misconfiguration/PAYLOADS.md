# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`cors-misconfiguration`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `cors-misconfiguration`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Origin reflection differential

**Expected differential:** the attacker Origin is echoed into Access-Control-Allow-Origin while a benign Origin yields the expected allowlisted value

```text
Origin: https://cors-probe.<assessor-controlled-host>
Origin: https://app.example (benign baseline for comparison)
```

### Null origin trust

**Expected differential:** Access-Control-Allow-Origin returns null for a null Origin, proving sandboxed-frame content is trusted

```text
Origin: null (sent from a sandboxed iframe or data: document)
```

### Credential pairing check

**Expected differential:** the response carries Access-Control-Allow-Credentials true together with the reflected origin, the condition that enables a credentialed read

```text
GET /api/me with Origin: https://cors-probe.<assessor-controlled-host> and the session cookie attached
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
