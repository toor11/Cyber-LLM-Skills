---
name: rsa-attacks-factorization
description: RSA factorisation attacks. Covers Fermat factorisation for close primes, shared primes across moduli, Pollard rho and p-1, and weak key generation. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: cryptography-attacks
tier: leaf
triggers: ["rsa factorization", "fermat attack", "shared prime", "pollard rho rsa"]
cwe: [CWE-326]
owasp: []
attack: []
capec: [CAPEC-463]
related: [rsa-attacks, rsa-attacks-small-and-low-exponent, rsa-attacks-padding-oracle, rsa-attacks-signature-forgery]
parent: rsa-attacks
---

# Rsa Attacks Factorization - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)

## Mechanism and Preconditions

Factorisation findings come from the key generator, not from the protocol. The cheap cases are arithmetic: two moduli that share a prime give it up to a GCD in milliseconds, and this happens in practice when a broken RNG or a cloned VM image produces keys from the same seed. Fermat factorisation is fast when `p` and `q` are close, because `n = a^2 - b^2` with `a = (p+q)/2` and small `b`; a generator that picks `p` then searches upward for the next prime produces exactly that structure, and the search terminates in a handful of iterations when the gap is small. Pollard's `p-1` succeeds when `p-1` is smooth, which is why generators that build primes as `k * small_product + 1` are dangerous. The general case — a well-generated 2048-bit modulus — is out of reach, so the review question is always "does this key have structure that a cheap method exploits", and the answer is an arithmetic check on public moduli rather than a code inspection. Multi-prime RSA and shared-prime across an estate are the two patterns that show up most often in real assessments.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you have two or more moduli **THEN** run the pairwise GCD first; it is the cheapest check and the most common real finding.
2. **IF** the generator picks `p` then `next_prime(p + delta)` with small `delta` **THEN** the branch is Fermat; the iteration count is `(p+q)/2 - sqrt(n)`.
3. **IF** the generator builds primes with a smooth `p-1` **THEN** Pollard `p-1` with a bounded exponent applies; state the bound you tried.
4. **IF** the modulus is well-formed, 2048 bits, and from a vetted generator **THEN** record `Not Feasible` with the method costs, and do not speculate.
5. **IF** the key is multi-prime (`openssl rsa -text` shows more than two primes) **THEN** the strength argument changes and needs its own treatment.
6. **IF** the finding is a leaked factor rather than a computed one **THEN** switch to [`lattice-and-advanced-crypto-attacks`](../lattice-and-advanced-crypto-attacks/SKILL.md) for the partial-information case.
7. **IF** the modulus is small enough for general factoring **THEN** that is a strength finding; report the bit length and the published cost rather than a method.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`rsa-attacks`](../rsa-attacks/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Collect moduli, not keys.** Extract every modulus from certificates, JWKS documents, firmware images, and configuration. The GCD sweep needs only these public values.
2. **Run the cheap methods in cost order.** Pairwise GCD, then Fermat with a bounded iteration count, then Pollard `p-1` with a bounded smoothness bound. Record the bound for each so the negative result has meaning.
3. **Choose the branch that produced structure.** A shared factor, a close-prime pair, or a smooth `p-1`. Each names a different generator defect and therefore a different remediation.
4. **Define the baseline-vs-probe differential.** Baseline: a modulus from a known-good generator, which no method factors within the bound. Probe: the suspect modulus, which factors within the same bound. The differential is the iteration count or the method that succeeded.
5. **Name the stop condition.** Stop at the first factor found within a documented bound. Do not raise bounds indefinitely; a negative result at a stated bound is the deliverable.
6. **State the proof.** Report the method, the bound, the iteration count, the recovered factor's bit length, and the generator defect it implies. For a shared factor, name both keys and the rotation that closes it.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| Two certificates whose moduli share a prime | A cloned or weakly seeded RNG at key generation; the factor is one GCD away | Certificate inventory, firmware key stores |
| `p` and `q` whose difference is under 2^20 | Fermat-solvable in a few thousand iterations, so the generator searched locally for the second prime | Embedded key generators, `openssl genrsa` with a bad patch |
| A modulus that factors under Pollard `p-1` with bound 10^5 | A smooth `p-1`, so the prime was constructed from a small factor base | Smart-card and HSM key generation |
| `openssl rsa -text` listing `prime1`, `prime2`, `prime3` | Multi-prime RSA, whose per-prime size and overall strength need a separate argument | Legacy `openssl genrsa -primes 3` |
| 2048-bit modulus from a vetted generator, no GCD collision | No cheap method applies; record `Not Feasible` with the bounds you tried | Modern TLS and signing keys |
| A 512-bit modulus in a firmware image | Strength finding: the factoring cost is within reach of a single machine | IoT firmware, legacy bootloaders |

## Worked Contrast

**Vulnerable: key generation that searches locally for the second prime**

```python
# Picking p then walking up to the next prime makes q - p small, so n = a^2 - b^2
# with tiny b: Fermat finds the factors in a few thousand iterations.
from sympy import nextprime, randprime

def weak_key(bits: int = 1024) -> tuple[int, int]:
    p = randprime(2 ** (bits - 1), 2 ** bits)
    q = nextprime(p + 2)          # q is a few steps from p
    return p * q, p
```

**Hardened: independent random primes with a documented separation check**

```python
# Two independent draws from the full range, with an explicit check that they are
# far apart and that neither p-1 nor q-1 is smooth over a small factor base.
from sympy import randprime
from math import isqrt

def strong_key(bits: int = 1024) -> tuple[int, int]:
    lo, hi = 2 ** (bits - 1), 2 ** bits
    while True:
        p = randprime(lo, hi)
        q = randprime(lo, hi)
        if p == q or abs(p - q) < 2 ** (bits // 2):
            continue                       # reject close primes (Fermat)
        if isqrt(p * q) ** 2 == p * q:
            continue
        return p * q, p
```

**Why this matters:** The left generator makes the two primes adjacent, which hands an attacker a quadratic-form factorisation that runs in a few thousand iterations regardless of key size. The right generator draws both primes independently from the full range and rejects pairs that are too close, which is exactly the property Fermat and its variants exploit.

## When It Is NOT This Issue

- **A shared modulus between a certificate and its own renewed version.** Reusing the key is a hygiene question, not a factorisation finding, unless the primes differ.
- **A modulus that fails a Fermat run at 10^6 iterations.** The negative result at a stated bound is the correct output; raising the bound until something happens is not analysis.
- **Multi-prime RSA with a documented per-prime size.** Three 1024-bit primes give roughly 3072-bit strength under the standard analysis; the finding needs a specific weakness.
- **A test key with a small modulus in a fixture.** Test vectors are small deliberately; confirm the path is not deployed.
- **Two keys generated on the same host at different times with a sound RNG.** Shared infrastructure is not shared primes; the GCD result is the only evidence that counts.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `rsa-attacks-factorization` based solely on surface keywords (`Fermat`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `rsa-attacks-factorization` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: rsa-attacks-factorization
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-326`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`rsa-attacks`](../rsa-attacks/SKILL.md) - Cryptography Attacks (flagship)
- [`rsa-attacks-small-and-low-exponent`](../rsa-attacks-small-and-low-exponent/SKILL.md) - Cryptography Attacks (leaf)
- [`rsa-attacks-padding-oracle`](../rsa-attacks-padding-oracle/SKILL.md) - Cryptography Attacks (leaf)
- [`rsa-attacks-signature-forgery`](../rsa-attacks-signature-forgery/SKILL.md) - Cryptography Attacks (leaf)
- [`classical-and-covert-encoding`](../classical-and-covert-encoding/SKILL.md) - Cryptography Attacks (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `rsa-attacks-factorization` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-326`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 1 |
| Top sources | CYBER_CPT/ctftime (6) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
