# Verification Probes and Expected Differentials

> Sub-skill: [`prng-and-nonce-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Generator identification

```text
# Which generator feeds a token or a key?
rg -n --no-heading "\brandom\.(random|randint|choice|getrandbits)|Math\.random|new Random\(|mt_rand|rand\(\)" -g '!test*'
rg -n --no-heading "secrets\.|os\.urandom|getrandom|SecureRandom|CSPRNG" -g '!test*'
```

Expected differential: a token sink reached only from the first group is the finding; the same sink reached from the second group is a control.

## Class 2 — Sequence-linearity probe (offline)

```text
# Fit an LCG to three consecutive observed integers; a small residual proves the fit.
python - <<'PRNGANDNONCEATCE18_CLASS2'
from math import gcd  # prng-and-nonce-attacks: class 2 sequencelinearity probe
seq = [int(x) for x in open("observed.txt").read().split()][:5]
d = [seq[i+1] - seq[i] for i in range(len(seq)-1)]
z = [abs(d[i+1]*d[i-1] - d[i]*d[i]) for i in range(1, len(d)-1)]
m = 0
for v in z: m = gcd(m, v)
print("modulus candidate:", m, "next predicted:", (seq[-1]*2 - seq[-2]) % m if m else "n/a")
PRNGANDNONCEATCE18_CLASS2
```

Expected differential: a modulus candidate that is a familiar power of two (2^31, 2^32, 2^48) plus a prediction that matches the next observed value is the finding. A large coprime modulus with no prediction match means the sequence is not LCG-derived.

## Class 3 — Seed-window probe

```text
# How many seeds must an attacker try? Count the plausible clock values only.
python - <<'PRNGANDNONCEATCE18_CLASS3'
window_seconds, pids = 3600, 4096          # one hour, typical pid space
print("seed candidates:", window_seconds * pids, "-> seconds at 1e6 tries/s:",
      window_seconds * pids / 1e6)
PRNGANDNONCEATCE18_CLASS3
```

Expected differential: no traffic. A candidate count below roughly 10^10 is a brute-force finding; above it, the seed space alone does not make the generator exploitable.

## Class 4 — Token-entropy probe

```text
# Collect distinct tokens from one account's issuance flow and measure the space.
python - <<'PRNGANDNONCEATCE18_CLASS4'
import collections  # prng-and-nonce-attacks: class 4 tokenentropy probe
toks = [l.strip() for l in open("tokens.txt")]
print("count:", len(toks), "distinct:", len(set(toks)),
      "min_len:", min(map(len, toks)), "alphabet:", len(set("".join(toks))))
PRNGANDNONCEATCE18_CLASS4
```

Expected differential: a width-alphabet product far below 2^128 is the quantitative finding; a CSPRNG at 32 bytes shows no collisions and no short widths.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
