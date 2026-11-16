# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`session-and-token-lifecycle-fixation-and-prediction`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `session-and-token-lifecycle-fixation-and-prediction`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### URL-parameter fixation

**Expected differential:** the post-login identifier equals the planted one only if supplied identifiers are honoured

```text
request /login with a planted sid parameter then authenticate and compare the session id
authenticate without supplying a sid and note the issued id
```

### Pre-set cookie fixation

**Expected differential:** a cookie set before login surviving it proves no rotation

```text
set a session cookie to an assessor-fixed value before posting credentials
clear the cookie and authenticate to see the minted id
```

### Sequence sampling for prediction

**Expected differential:** consecutively issued identifiers that increment or track time prove a weak generator

```text
request the landing page ten times and record each issued session id in order
compare the deltas between consecutive identifiers for a pattern
```

### Keyspace estimate

**Expected differential:** a short identifier alphabet indicates an enumerable space

```text
measure the length and character set of a freshly issued session id
estimate the bits of entropy against a 128-bit reference
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
