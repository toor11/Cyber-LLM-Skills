# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`jwt-attacks-secret-cracking`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `jwt-attacks-secret-cracking`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Offline key-candidate differential (no live traffic)

**Expected differential:** a captured HS256 token is tested against a wordlist offline; a weak secret yields a matching recomputed signature while a random key does not, and no requests reach the target

```text
captured HS256 token tested against a wordlist offline
same token tested with a random 256-bit key (control, no match)
```

### Weak-secret recompute probe

**Expected differential:** re-signing the unchanged claims with a candidate secret and comparing the signature to the captured one confirms the secret without contacting the server

```text
candidate secret = dictionary word, recompute the signature
candidate secret = high-entropy random, recompute the signature (control)
```

### Algorithm pre-screen

**Expected differential:** reading the header alg before any cracking effort separates HS (crackable shared secret) from RS or ES (no offline crack)

```text
header alg=HS256 (shared secret, offline-crackable)
header alg=RS256 (asymmetric, not offline-crackable)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
