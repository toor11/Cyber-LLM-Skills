---
name: prng-and-nonce-attacks
description: "Exploits weak randomness: predictable PRNG seeds, time-based tokens, nonce and IV reuse, and biased generators. Use when tokens, keys, session IDs or signatures depend on random values."
family: cryptography-attacks
tier: core
triggers: ["predictable random", "prng weakness", "seed prediction", "nonce reuse", "weak randomness"]
cwe: [CWE-338]
owasp: []
attack: []
capec: [CAPEC-59]
related: [prng-and-nonce-attacks-predictable-token-generation, prng-and-nonce-attacks-signature-nonce-reuse, classical-and-covert-encoding, symmetric-cipher-attacks]
---

# PRNG and Nonce Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **core** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)

## Mechanism and Preconditions

A predictable random number is a key-recovery primitive, not a weakness in the surrounding protocol. Four constructions matter in review. Mersenne Twister (MT19937) has 19937 bits of state and is tempered-linear: 624 consecutive 32-bit outputs recover the state exactly, and from the state every past and future output is computable, so a token sequence from `random` in Python or `Math.random`-derived identifiers in JS is reconstructible given a window of outputs. LCG-based generators, including the classic `rand()` families and Java's `java.util.Random`, are affine, so three consecutive outputs determine the modulus and multiplier and the whole sequence follows. Time-seeded generators collapse the entropy to the number of plausible seed values — often a second-resolution window times a small process-id space — which is a brute-force problem measured in thousands, not billions. The fourth is bias from modulo reduction: taking `uniform(0, 2^32) % n` over-represents low residues whenever `n` does not divide `2^32`, which matters for nonces and for anything that must be uniform. The precondition is always observability: an attacker needs outputs, and most real findings come from tokens that are displayed, or from identifiers that appear in URLs, before being used as a secret.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the observed values are numeric and sequential-looking **THEN** test the sequence for linearity before anything else; three outputs are enough to fit an LCG and 624 are enough for MT19937.
2. **IF** the generator is a general-purpose PRNG (`random`, `Math.random`, `java.util.Random`, `rand()`) **THEN** it is unsuitable for tokens, nonces, and keys regardless of seeding; the finding stands on the API, not on the sample.
3. **IF** a token is short and observable **THEN** switch to [`prng-and-nonce-attacks-predictable-token-generation`](../prng-and-nonce-attacks-predictable-token-generation/SKILL.md) for the token-specific arithmetic.
4. **IF** the value is a signing nonce **THEN** switch to [`prng-and-nonce-attacks-signature-nonce-reuse`](../prng-and-nonce-attacks-signature-nonce-reuse/SKILL.md); the consequence is key recovery, not guessability.
5. **IF** the reduction is `% n` on a wide uniform value **THEN** quantify the bias; it matters for nonces only when `n` is close to the modulus.
6. **IF** the generator is `secrets`, `os.urandom`, `getrandom`, or a `CSPRNG` wrapper **THEN** the disposition is a control, and the remaining question is only whether the output is truncated.
7. **IF** the value never leaves the process and is never used as a secret **THEN** it is not a finding; say which property it feeds.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `prng-and-nonce-attacks-predictable-token-generation` | [`prng-and-nonce-attacks-predictable-token-generation`](../prng-and-nonce-attacks-predictable-token-generation/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `prng-and-nonce-attacks-signature-nonce-reuse` | [`prng-and-nonce-attacks-signature-nonce-reuse`](../prng-and-nonce-attacks-signature-nonce-reuse/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Name the sink.** A PRNG finding needs a consumer: a session token, a password-reset code, a nonce, a key, or an identifier that is treated as a capability. Record the sink and whether the value is observable before use.
2. **Identify the generator from the import or the API.** `random`, `Math.random`, `java.util.Random`, `rand()`, and `mt_rand` are non-cryptographic by contract. A CSPRNG wrapper is a control. There is rarely a need to sample.
3. **Choose the branch.** State recovery (MT19937 or LCG), seed brute force (time or pid seeding), bias (modulo reduction), or truncation (only `k` bits of a good generator retained).
4. **Define the baseline-vs-probe differential.** Baseline: two independent generators produce sequences with no linear relation. Probe: fit a linear recurrence to the observed sequence and predict the next value; a correct prediction is the finding, and one wrong prediction is not proof of safety.
5. **Name the stop condition.** Stop at the first correctly predicted value the attacker could not otherwise know. Do not recover a full MT state or brute-force seed spaces on a live service.
6. **State the proof.** Report the generator, its API contract, the sink, the number of observed outputs, and the prediction that succeeded. If the prediction fails, record `Not Reproduced` and say whether that is because the generator is sound or because the sample was too small.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `random.randint(...)` or `Math.random()` feeding a token | Non-cryptographic generator by contract, so the token's entropy is bounded by the state, not by the API's apparent range | Python `random`, JS `Math.random`, `java.util.Random` |
| 624 consecutive 32-bit outputs available | MT19937 state recovery, after which every past and future output is computable | Python `random.getrandbits`, PHP `mt_rand` |
| `srand(time(NULL))` or `new Random(System.currentTimeMillis())` | Seed space is the plausible clock window, which brute force covers in seconds | C, Java, older PHP |
| Tokens that differ by a constant increment | LCG or counter, so the next token is arithmetic rather than a guess | Home-rolled generators, poorly seeded `rand()` |
| `secrets.token_urlsafe(32)` | CSPRNG with adequate width; a control, and the remaining question is only storage | CPython `secrets`, Django `get_random_string` |
| `int.from_bytes(os.urandom(4)) % 1000000` for a reset code | Only a million values and non-uniform, so the code is guessable regardless of the source quality | Password-reset implementations |

## Worked Contrast

**Vulnerable: session token from a non-cryptographic PRNG seeded from the clock**

```python
# random is MT19937: 624 observed outputs recover the state, so a token sequence is
# reconstructible. Seeding from the clock removes even that much work.
import random, time

random.seed(int(time.time()))

def new_session_token() -> str:
    return "".join(random.choice("abcdef0123456789") for _ in range(32))
```

**Hardened: CSPRNG with full width and no truncation**

```python
# secrets draws from the OS CSPRNG; 32 bytes of entropy makes the token space
# 2^256 and there is no state to recover from observed values.
import secrets

def new_session_token() -> str:
    return secrets.token_urlsafe(32)          # 256 bits, URL-safe alphabet
```

**Why this matters:** The left token is deterministic given a seed the attacker can bracket to a few thousand candidate seconds, and even without the seed the MT state is recoverable from enough outputs. The right token has no recoverable state and no seed, so observing any number of tokens reveals nothing about the next one.

## When It Is NOT This Issue

- **`random` used for jitter, backoff, sampling, or test data.** No secret and no capability, so the generator's predictability is irrelevant. Say what the value feeds.
- **`Math.random()` used for a UI animation or a non-security identifier.** Not a capability unless the identifier grants access; trace the consumer before filing.
- **A CSPRNG whose output is truncated to 128 bits.** Still infeasible to guess; the truncation is a note, not a finding.
- **A time-seeded generator whose output never leaves the process.** Seed brute force needs an observable output to compare against.
- **`mt_rand` in a legacy path that has been replaced but not deleted.** Dead code; note it as cleanup unless the old path is still routable.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `prng-and-nonce-attacks` based solely on surface keywords (`mt19937`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `prng-and-nonce-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: prng-and-nonce-attacks
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-338`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`prng-and-nonce-attacks-predictable-token-generation`](../prng-and-nonce-attacks-predictable-token-generation/SKILL.md) - Cryptography Attacks (leaf)
- [`prng-and-nonce-attacks-signature-nonce-reuse`](../prng-and-nonce-attacks-signature-nonce-reuse/SKILL.md) - Cryptography Attacks (leaf)
- [`classical-and-covert-encoding`](../classical-and-covert-encoding/SKILL.md) - Cryptography Attacks (leaf)
- [`symmetric-cipher-attacks`](../symmetric-cipher-attacks/SKILL.md) - Cryptography Attacks (core)
- [`block-cipher-modes-and-padding-oracles`](../block-cipher-modes-and-padding-oracles/SKILL.md) - Cryptography Attacks (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `prng-and-nonce-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-338`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 9 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/ctftime (5), cyber-security/security-code (1), hackerone_disclosed_reports (1), cyber-security/CyberSec-Dataset (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
