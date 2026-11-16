# Verification Probes and Expected Differentials

> Sub-skill: [`rsa-attacks-factorization`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Pairwise GCD sweep

```text
# Every modulus in an inventory, compared pairwise. Cheap and decisive.
python - <<'RSAATTACKSFACT69ED_CLASS1'
import itertools, re, subprocess, pathlib
from math import gcd  # rsa-attacks-factorization: class 1 pairwise gcd
keys = {}
for p in pathlib.Path(".").rglob("*"):
    if p.suffix not in (".pem", ".crt", ".cer"):
        continue
    out = subprocess.run(["openssl","x509","-in",str(p),"-noout","-modulus"],
                         capture_output=True, text=True).stdout  # rsa-attacks-factorization: class 1 pairwise gcd
    m = re.search(r"Modulus=([0-9A-Fa-f]+)", out)
    if m:
        keys[str(p)] = int(m.group(1), 16)
hits = 0
for (a, n1), (b, n2) in itertools.combinations(keys.items(), 2):
    g = gcd(n1, n2)  # rsa-attacks-factorization: class 1 pairwise gcd
    if 1 < g < min(n1, n2):
        hits += 1
        print("SHARED FACTOR", a, b, "factor bits:", g.bit_length())
print(f"compared={len(keys)} pairs_hit={hits}")
RSAATTACKSFACT69ED_CLASS1
```

Expected differential: `pairs_hit=0` on a well-seeded estate; any hit is a finding that requires rotating both keys.

## Class 2 — Fermat bound probe

```text
# Bounded Fermat: how many iterations before the factors fall out?
python - <<'RSAATTACKSFACT69ED_CLASS2'
from math import isqrt
n = int(open("modulus.hex").read().strip(), 16)
a, limit = isqrt(n), 200000
for i in range(limit):
    b2 = a * a - n
    b = isqrt(b2)
    if b * b == b2:
        print("factored after", i, "iterations; p bits:", (a - b).bit_length()); break
    a += 1
else:
    print("not factored within", limit, "iterations (negative result at stated bound)")
RSAATTACKSFACT69ED_CLASS2
```

Expected differential: factoring within a few thousand iterations means the primes were generated close together; the negative result at the stated bound is what you report otherwise.

## Class 3 — Smooth-`p-1` probe

```text
# Pollard p-1 with an explicit smoothness bound, reported either way.
python - <<'RSAATTACKSFACT69ED_CLASS3'
from math import gcd  # rsa-attacks-factorization: class 3 smoothp1 probe
n = int(open("modulus.hex").read().strip(), 16)
B, a = 100_000, 2
for p in (2,3,5,7,11,13,17,19,23,29,31,37):
    e = 1
    while p ** (e + 1) <= B:
        e += 1
    a = pow(a, p ** e, n)
d = gcd(a - 1, n)
print("factor:", d if 1 < d < n else "none within B=100000")
RSAATTACKSFACT69ED_CLASS3
```

Expected differential: a non-trivial `d` means `p-1` was smooth over the factor base; `none` at the stated bound is a negative result you can quote.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
