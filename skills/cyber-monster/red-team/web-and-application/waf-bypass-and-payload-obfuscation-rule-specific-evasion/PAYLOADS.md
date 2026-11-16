# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`waf-bypass-and-payload-obfuscation-rule-specific-evasion`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `waf-bypass-and-payload-obfuscation-rule-specific-evasion`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Engine fingerprint (benign)

**Expected differential:** each vendor returns a distinct block or challenge signature to a harmless trigger, identifying the engine

```text
GET /?wafprobe-fp=1 (harmless canary to elicit a vendor block page)
User-Agent: wafprobe-fingerprint/1.0
```

### Canonical versus engine-specific form

**Expected differential:** the canonical trigger is blocked by the named engine while the engine-specific variant reaches the origin

```text
x=wafprobe-canary-generic (canonical trigger for this rule set)
x=wafprobe-canary-variant (engine-specific syntactic form)
```

### Scan-threshold probe

**Expected differential:** a body padded beyond the engine's inspected-size limit is forwarded unscanned while a small body is scanned

```text
field=wafprobe-small (within scan limit, expect inspected)
field=wafprobe-large&pad=<benign-filler-beyond-128kb> (beyond scan limit)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
