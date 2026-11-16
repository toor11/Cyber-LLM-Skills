---
name: password-hashing-and-kdf-attacks
description: "Attacks password storage and key derivation: fast-hash cracking, salting gaps, weak KDF parameters, and offline attack economics. Use when assessing how passwords or keys are stored or derived."
family: cryptography-attacks
tier: core
triggers: ["password hash attack", "bcrypt cost", "pbkdf2 weakness", "kdf attack", "unsalted hash"]
cwe: [CWE-916]
owasp: []
attack: []
capec: [CAPEC-55]
related: [classical-and-covert-encoding, symmetric-cipher-attacks, block-cipher-modes-and-padding-oracles, hash-attacks-and-length-extension]
---

# Password Hashing and Kdf Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **core** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)

## Mechanism and Preconditions

Password storage fails for reasons that are almost never "the hash is broken". The first is speed: SHA-256 and MD5 are designed to be fast, so a GPU evaluates billions of candidates per second, and a leaked table of SHA-256 digests is a dictionary lookup rather than an attack. The defence is a work factor — bcrypt's cost, scrypt's `N/r/p`, Argon2id's memory and iteration parameters — chosen so one verification costs the defender milliseconds and the attacker's per-candidate cost rises by the same factor. The second is salt: without a unique per-user salt, identical passwords produce identical digests, so one precomputed table covers the whole table and a single cracked entry reveals every user who shares that password. The third is the pepper and the KDF's output handling: a global pepper must live outside the database, and a KDF whose output is truncated or whose parameters are stored unauthenticated can be downgraded. The fourth is the migration path, which is where real systems fail: a legacy unsalted MD5 column kept for "compatibility" with a `if (legacy) ... else ...` branch means the weak path stays reachable, and often the branch is chosen by attacker-controlled data. Reviewing this skill means measuring the work factor against current hardware, not checking for a named algorithm.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the stored value has no per-user salt, or the salt is the username **THEN** that is the finding regardless of the algorithm; state the precomputation consequence.
2. **IF** the algorithm is a fast hash (MD5, SHA-1, SHA-256, SHA-512) with no work factor **THEN** measure the hash rate on current hardware and compute the crack time for a realistic password distribution.
3. **IF** the algorithm is bcrypt **THEN** read the cost from the stored hash prefix (`$2b$12$`) and compare against the current floor; a cost of 4 or 5 is the finding.
4. **IF** the algorithm is Argon2id **THEN** read the memory and iteration parameters from the encoded hash and check them against current guidance; memory below 19 MiB is weak.
5. **IF** a legacy verification branch exists **THEN** check what selects it; if it is derived from the stored value or a request field, the attacker picks the weakest path.
6. **IF** the KDF protects a key rather than a password **THEN** the same work-factor argument applies but the threat is offline guessing against a ciphertext; state the attacker's budget.
7. **IF** the review is about a hash used as a MAC or an identifier **THEN** switch to [`hash-attacks-and-length-extension`](../hash-attacks-and-length-extension/SKILL.md); this skill is about guessability.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the stored format.** Extract the algorithm identifier, the cost parameters, and the salt length from an actual stored value, not from the code's default. A default of cost 12 with legacy rows at cost 4 means the population is at cost 4.
2. **Quantify the work.** For a fast hash, measure hashes per second on a representative GPU. For bcrypt and Argon2, convert the parameters to a per-guess cost and multiply by the candidate space of the password policy.
3. **Choose the branch.** No salt (precomputation), fast hash (speed), low cost (tuning), downgrade path (migration), or pepper placement (custody).
4. **Define the baseline-vs-probe differential.** Baseline: a verification of a known password takes the expected time and matches. Probe: the same verification against a legacy row takes a measurably shorter time, which proves a weaker work factor for that population. The differential is the time ratio, not a cracked password.
5. **Name the stop condition.** Stop when you have the parameter inventory and the crack-time estimate for the weakest reachable row. Do not crack any user's password, and do not build a rainbow table.
6. **State the proof.** Report the weakest stored format found, the parameters, the measured per-guess cost, the candidate-space estimate from the password policy, and the rehash-on-login plan. If every row meets the current floor, the disposition is `Verified Safe` with the parameters cited.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `hashlib.sha256(password).hexdigest()` stored with no salt | Fast hash, so the whole table is crackable at GPU rates with no precomputation needed | Legacy PHP, Django without `make_password` |
| `$2b$04$...` in the stored column | bcrypt at cost 4, roughly 2^4 iterations — three orders of magnitude below a current floor | bcrypt rows written by an old framework default |
| `$argon2id$v=19$m=8192,t=2,p=1$...` | Argon2id with 8 MiB memory, below the current 19 MiB guidance | Modern libraries with legacy parameters |
| `bcrypt.hashpw(pw, bcrypt.gensalt())` with no rounds argument | Library default cost, which may lag the current recommendation | Python `bcrypt`, `passlib` |
| A `verify_legacy()` branch selected by `hash.startswith("md5$")` | The attacker can select the weakest path by presenting a value that looks legacy | Migration shims, "support both" code |
| `scrypt(pw, salt, n=2**14, r=8, p=1)` with per-user random salt | Meets a defensible baseline; record the parameters as the control | Python `hashlib.scrypt`, Node `crypto.scrypt` |

## Worked Contrast

**Vulnerable: unsalted fast hash with an attacker-selectable legacy branch**

```python
# Unsalted SHA-256 means identical passwords collide and one table cracks everyone.
# The legacy branch is chosen from the stored value, so a downgrade is one UPDATE away.
import hashlib

def store(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()          # no salt, no work factor

def verify(pw: str, stored: str) -> bool:
    if stored.startswith("md5$"):                            # attacker-influenced path
        return hashlib.md5(pw.encode()).hexdigest() == stored[4:]
    return hashlib.sha256(pw.encode()).hexdigest() == stored
```

**Hardened: Argon2id with per-user salt, tuned parameters, and no weak branch**

```python
# A unique salt per user and a memory-hard KDF. Legacy rows are rehashed on
# successful login and the branch is never chosen by the stored value.
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

PH = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)

def store(pw: str) -> str:
    return PH.hash(pw)                     # embeds salt and parameters in the string

def verify(pw: str, stored: str) -> bool:
    try:
        PH.verify(stored, pw)
    except VerifyMismatchError:
        return False
    if PH.check_needs_rehash(stored):      # transparent upgrade, no weak branch
        raise NeedsRehash(PH.hash(pw))
    return True
```

**Why this matters:** The left store gives an attacker a table-wide dictionary attack with no per-user cost, and the `md5$` prefix lets anyone who can write the column move a victim onto the weakest path. The right store makes every guess expensive and per-user, and it upgrades parameters on login instead of keeping a second, weaker verifier reachable.

## When It Is NOT This Issue

- **A fast hash on a value that is not a password.** API keys, session identifiers, and reset tokens are high-entropy, so a fast hash is appropriate and the work factor would only add latency.
- **A bcrypt cost that looks low but is fronted by a rate limiter and a lockout.** The rate limit changes the online attacker's budget; state both controls rather than the cost alone.
- **A salt derived from the user id.** It is unique per user, so the precomputation argument is closed even though the salt is predictable; note the weaker property.
- **A legacy column that is read-only and no longer accepts new writes.** The exposure is bounded by the population; say how many rows and whether they can still authenticate.
- **Argon2 parameters stored inside the hash string.** That is the correct design; the parameters being visible is not a leak.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `password-hashing-and-kdf-attacks` based solely on surface keywords (`bcrypt cost`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `password-hashing-and-kdf-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: password-hashing-and-kdf-attacks
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-916`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`classical-and-covert-encoding`](../classical-and-covert-encoding/SKILL.md) - Cryptography Attacks (leaf)
- [`symmetric-cipher-attacks`](../symmetric-cipher-attacks/SKILL.md) - Cryptography Attacks (core)
- [`block-cipher-modes-and-padding-oracles`](../block-cipher-modes-and-padding-oracles/SKILL.md) - Cryptography Attacks (core)
- [`hash-attacks-and-length-extension`](../hash-attacks-and-length-extension/SKILL.md) - Cryptography Attacks (core)
- [`rsa-attacks`](../rsa-attacks/SKILL.md) - Cryptography Attacks (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `password-hashing-and-kdf-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-916`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 9 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/oxdf (4), CYBER_CPT/github_security_md (3), OffsecCyber (1), CYBER_CPT/osv (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
