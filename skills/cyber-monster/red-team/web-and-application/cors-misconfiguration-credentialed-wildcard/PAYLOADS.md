# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`cors-misconfiguration-credentialed-wildcard`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `cors-misconfiguration-credentialed-wildcard`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Arbitrary subdomain acceptance

**Expected differential:** an attacker-style sibling subdomain is echoed with credentials true while a real subdomain is the control

```text
Origin: https://wildcard-probe.target.example (arbitrary sibling, expect echo + creds)
Origin: https://portal.target.example (legitimate sibling baseline)
```

### Wildcard-plus-credentials inspection

**Expected differential:** the response simultaneously carries a wildcard allow-origin and credentials true, an illegal pairing exposing a dynamic echo bug

```text
GET /api/profile with Origin: https://any.site.invalid and the session cookie present
```

### Suffix-rule boundary probe

**Expected differential:** a lookalike parent that merely ends with the trusted string is accepted, proving an endsWith rather than an FQDN set

```text
Origin: https://target.example.attacker-cdn.net (suffix-confusion host)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
