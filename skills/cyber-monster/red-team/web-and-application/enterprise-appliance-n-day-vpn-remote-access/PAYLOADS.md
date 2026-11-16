# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`enterprise-appliance-n-day-vpn-remote-access`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `enterprise-appliance-n-day-vpn-remote-access`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Firmware fingerprint

**Expected differential:** the portal reveals a model and build in or out of an affected range, versus a hardened portal that strips version markers

```text
GET /remote/login then read the portal title, asset hashes, and Server header
openssl s_client to the gateway and read the certificate CN for the model
```

### Pre-auth endpoint reachability

**Expected differential:** a diagnostic or locale endpoint answers with no session, versus a patched build returning 404 or a login redirect

```text
GET /sslvpn/portal/locale/en.json as a benign locale fetch, expect 200
repeat the locale fetch with no session cookie to confirm it is pre-auth
```

### Traversal reachability marker

**Expected differential:** a traversal form reaches a world-readable non-sensitive marker and reverts to 404 once canonicalisation is enforced; no credential files are requested

```text
lang=../../../../etc/hostname as a benign host marker, read status only
lang=en as the baseline locale, compare body length
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
