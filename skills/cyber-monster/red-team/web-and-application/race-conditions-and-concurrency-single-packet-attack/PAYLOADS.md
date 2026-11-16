# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`race-conditions-and-concurrency-single-packet-attack`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `race-conditions-and-concurrency-single-packet-attack`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### HTTP/2 single-packet

**Expected differential:** the impossible committed state appears only when streams share one packet

```text
Turbo Intruder: gate='race1', engine=Engine.BURP (HTTP/2 single-packet)
```

### HTTP/1.1 last-byte sync

**Expected differential:** releasing the withheld final bytes together produces the divergence on an HTTP/1.1 origin

```text
HTTP/1.1 last-byte sync over pipelined keep-alive connections
```

### First-sequence-sync scaling

**Expected differential:** synchronizing only the final sequence lets the burst exceed the TCP window for large N

```text
first-sequence-sync to exceed the 65535-byte window for ~10000 requests
```

### Aligned-versus-spaced control

**Expected differential:** a spaced control of the same requests produces no divergence, isolating timing as the variable

```text
control: identical requests spaced 200 ms apart (expect no divergence)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
