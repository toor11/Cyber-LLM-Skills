---
name: prng-and-nonce-attacks-predictable-token-generation
description: Predictable token generation. Covers recovering PRNG state from observed tokens, time-seeded generators, and predicting password reset and session values. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: cryptography-attacks
tier: leaf
triggers: ["predictable token", "prng state recovery", "time seeded token"]
cwe: [CWE-338]
owasp: []
attack: []
capec: [CAPEC-59]
related: [prng-and-nonce-attacks, prng-and-nonce-attacks-signature-nonce-reuse, classical-and-covert-encoding, symmetric-cipher-attacks]
parent: prng-and-nonce-attacks
---

# PRNG and Nonce Attacks Predictable Token Generation - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)

## Mechanism and Preconditions

Predictable token generation is the token-level consequence of a weak PRNG, and it is worth its own skill because the arithmetic is different: the attacker does not need to recover generator state, only to enumerate the token space. The space is the product of the alphabet size and the token length, minus whatever the generator removes. A six-digit numeric reset code has `10^6` values, which is one second of requests at a modest rate; an eight-character base32 token has `32^8 = 2^40`, which is feasible offline if the verifier is a stored hash with no rate limit; a UUIDv1 leaks a timestamp and a MAC-derived node identifier, so the random-looking part is not random at all. The second failure is that the token is bound to nothing: a reset code that is not tied to the user it was issued to, or a token that stays valid after use, converts the search into a shareable capability. The third is observability: a token that appears in a URL, a `Referer` header, or a log is compromised before it is used. The review therefore asks three things — how big is the space, what is the verifier's attempt budget, and is the token bound to its subject and its single use.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the token is numeric and shorter than 12 digits **THEN** compute the space and the verifier's rate limit before anything else; the ratio is the finding.
2. **IF** the token is a UUID **THEN** identify the version; v1 and v4-with-a-weak-source are timestamp- or PRNG-derived, while v4 from a CSPRNG is 122 bits.
3. **IF** the token is not bound to a user, an action, or an expiry **THEN** that is the finding regardless of entropy, because it is a bearer capability for anything.
4. **IF** the token remains valid after a successful use **THEN** record the replay window and its size.
5. **IF** the token appears in a query string, an email link, or a log line **THEN** add the exposure path; entropy does not help a leaked token.
6. **IF** the verifier has no attempt limit and no lockout **THEN** the search is online and the space size is the only bound.
7. **IF** the review is about the generator's internal state **THEN** switch to [`prng-and-nonce-attacks`](../prng-and-nonce-attacks/SKILL.md); this skill is about the space and the binding.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`prng-and-nonce-attacks`](../prng-and-nonce-attacks/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Measure the space from the format.** Record the alphabet, the length, and any structure (a prefix, a checksum, a timestamp). Compute `alphabet^length` and subtract any predictable component. A checksum reduces the effective space by its width.
2. **Read the verifier's budget.** Attempts per token before invalidation, rate limits per IP and per account, lockout policy, and whether failures are distinguishable. The finding is the ratio of the space to the budget, not the space alone.
3. **Choose the branch.** Small space (enumerable), weak binding (bearer capability), no single use (replay), or leaked channel (observable). Each has a different fix and a different severity.
4. **Define the baseline-vs-probe differential.** Baseline: a valid token works once. Probe one: an invalid token from just outside the space is rejected identically to one from inside it, which tells you whether the verifier leaks proximity. Probe two: the same valid token used twice, where the second success is the replay finding.
5. **Name the stop condition.** Stop at the first successful use of a token the attacker should not hold, or at the demonstrated absence of a binding. Do not enumerate a live service's token space.
6. **State the proof.** Report the format, the computed space, the verifier's budget, the binding fields present or absent, and the replay result. If the space exceeds the budget by a wide margin and the token is bound and single-use, the disposition is `Verified Safe` with the numbers shown.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| A six-digit code compared with `==` and no attempt counter | Space of `10^6` against an unlimited budget, so enumeration is a matter of minutes | Password-reset and MFA flows |
| `uuid.uuid1()` used as an invitation token | Timestamp and node identifier are embedded, so the random component is far smaller than it looks | Python and Java UUIDv1 call sites |
| Reset token not stored against a user id | Bearer capability: whoever holds it resets anyone's password | Token table schema, session stores |
| Token row with no `used_at` or `consumed` column | Replay is possible for the token's lifetime | Token storage schema |
| `secrets.token_urlsafe(32)` plus a bound subject and a single-use flag | Meets the space, binding, and replay requirements; record as the control | Modern reset flows |
| Token echoed in a `Location` header or an email link with a long TTL | Exposure plus long validity; the entropy does not survive the leak | Redirect-based and email-based flows |

## Worked Contrast

**Vulnerable: short numeric code, unbound, reusable, unlimited attempts**

```python
# 10^6 codes, no attempt limit, not stored against a user, never marked used: the
# capability is enumerable and transferable.
import random

def issue_reset(email: str) -> str:
    code = f"{random.randint(0, 999999):06d}"
    CACHE.set(f"reset:{code}", email, ttl=86400)      # not keyed by user
    return code

def redeem(code: str) -> str:
    return CACHE.get(f"reset:{code}")                  # still valid after use
```

**Hardened: wide CSPRNG token, bound to the subject, single use, attempt-limited**

```python
# 256 bits of entropy, stored against the user with a hash, marked consumed on use,
# and counted per account so enumeration cannot exceed a small budget.
import hashlib, secrets

def issue_reset(user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    DB.execute("INSERT INTO reset(user_id, token_hash, expires_at, used_at, attempts) "
               "VALUES (?, ?, now() + interval '15 minutes', NULL, 0)",
               (user_id, hashlib.sha256(token.encode()).digest()))
    return token

def redeem(user_id: str, token: str) -> bool:
    row = DB.one("SELECT id, used_at, attempts FROM reset WHERE user_id=? AND token_hash=?",
                 (user_id, hashlib.sha256(token.encode()).digest()))
    if not row or row.used_at is not None or row.attempts >= 5:
        DB.execute("UPDATE reset SET attempts = attempts + 1 WHERE user_id=?", (user_id,))
        return False
    DB.execute("UPDATE reset SET used_at = now() WHERE id=?", (row.id,))
    return True
```

**Why this matters:** The left code is enumerable in a million requests, works for any account, and keeps working after the first use, so the same value can be replayed by whoever sees it. The right code makes the search `2^256`, binds the token to the subject so it cannot be transferred, consumes it on first success, and caps attempts per account so even a lucky guess is bounded.

## When It Is NOT This Issue

- **A short code combined with a hard attempt limit and a per-account lockout.** The space is small but the budget is smaller; state both numbers and close it.
- **A UUIDv4 from a CSPRNG.** 122 bits of entropy with no embedded structure; the format is not the problem.
- **A token that appears in a URL but is single-use and expires in minutes.** The exposure window is bounded; note it as a design trade-off with the TTL cited.
- **An invitation token bound to an email address that must match at redemption.** The binding closes the transfer argument even when the token is long-lived.
- **A numeric idempotency key.** It identifies a request, not a capability; trace what it grants before filing.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `prng-and-nonce-attacks-predictable-token-generation` based solely on surface keywords (`mt19937`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `prng-and-nonce-attacks-predictable-token-generation` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: prng-and-nonce-attacks-predictable-token-generation
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-338`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`prng-and-nonce-attacks`](../prng-and-nonce-attacks/SKILL.md) - Cryptography Attacks (core)
- [`prng-and-nonce-attacks-signature-nonce-reuse`](../prng-and-nonce-attacks-signature-nonce-reuse/SKILL.md) - Cryptography Attacks (leaf)
- [`classical-and-covert-encoding`](../classical-and-covert-encoding/SKILL.md) - Cryptography Attacks (leaf)
- [`symmetric-cipher-attacks`](../symmetric-cipher-attacks/SKILL.md) - Cryptography Attacks (core)
- [`block-cipher-modes-and-padding-oracles`](../block-cipher-modes-and-padding-oracles/SKILL.md) - Cryptography Attacks (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `prng-and-nonce-attacks-predictable-token-generation` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-338`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/go_exploitdb (3), CYBER_CPT/xz_aliyun (2), CYBER_CPT/ctftime (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
