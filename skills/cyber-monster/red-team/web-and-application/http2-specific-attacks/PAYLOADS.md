# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`http2-specific-attacks`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `http2-specific-attacks`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Concurrency-limit baseline (bounded)

**Expected differential:** driving streams up to the advertised limit without resets yields stable backend latency, establishing the reference the reset pattern must exceed

```text
open streams up to SETTINGS_MAX_CONCURRENT_STREAMS, no resets, measure latency (baseline)
read the server SETTINGS frame to record the advertised stream limit (limit read)
```

### Server-sent reset accounting probe (MadeYouReset, bounded)

**Expected differential:** a bounded set of streams crafted to provoke server RST_STREAM leaves backend handlers running while slots free, so backend concurrency exceeds the limit versus the baseline

```text
send a small, bounded batch of streams that each provoke a server reset, measure backend concurrency
compare backend concurrency to the advertised stream limit (MadeYouReset differential)
```

### h2c upgrade surface check

**Expected differential:** an h2c upgrade accepted on a cleartext connection reveals a smuggling path the front end did not mediate, versus a rejected upgrade

```text
send an HTTP/1.1 Upgrade: h2c request and observe whether a 101 switch occurs (upgrade probe)
send a plain HTTP/1.1 request with no Upgrade header (upgrade control)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
