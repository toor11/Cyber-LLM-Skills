# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`web-cache-poisoning-and-deception-cdn-specific-behaviour`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `web-cache-poisoning-and-deception-cdn-specific-behaviour`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### CDN identification

**Expected differential:** the cache-status header names the fronting product and its key field

```text
GET /?cdnprobe=1 (read cf-cache-status / x-served-by / x-amz-cf-id)
HEAD / (inspect edge headers without a body)
```

### Cross-form key collision (busted)

**Expected differential:** two URL forms share one edge key, shown by a hit on the second after storing the first

```text
GET /p/report?lang=en&cb=cdn-aaaa (store English body)
GET /p/report?lang=fr&cb=cdn-aaaa (expect cached English body on HIT)
```

### Encoded-path normalisation

**Expected differential:** the edge normalises an encoded slash or dot segment the origin routes differently

```text
GET /static/..%2faccount/profile?cb=cdn-bbbb
GET /static/../account/profile?cb=cdn-bbbb (decoded control)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
