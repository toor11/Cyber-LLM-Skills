# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`websocket-security`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `websocket-security`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Same-origin handshake baseline

**Expected differential:** the legitimate Upgrade with the app's own Origin returns 101, capturing the exact shape the cross-origin attempt must reproduce

```text
GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nOrigin: https://app.example
wssocket-baseline: Sec-WebSocket-Version: 13 with session cookie present
```

### Cross-origin handshake differential

**Expected differential:** the same handshake with a foreign Origin plus the session cookie still returns 101, proving the Origin invariant is missing

```text
GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nOrigin: https://wssocket-attacker.example
Origin: null (sandboxed iframe handshake)
```

### Per-message authorization probe

**Expected differential:** after a low-privilege handshake, a message requesting privileged data is accepted, proving authorization exists only at the handshake

```text
{"type":"subscribe","channel":"wssocket-admin-events"}
{"type":"get","resource":"wssocket-other-user-profile"}
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
