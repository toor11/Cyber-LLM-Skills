# Verification Probes and Expected Differentials

> Sub-skill: [`lattice-and-advanced-crypto-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Leak inventory and bound arithmetic

```text
# Enumerate every code path that returns a function of p, q, or d.
rg -n --no-heading "\bp\b|private_numbers|\.d\b|factor" -g '*report*' -g '*debug*' -g '!test*'
```

Expected differential: a report that returns only the modulus and a public fingerprint is a control; anything returning bits of `p`, `q`, or `d` is the leak.

```text
# The bound comparison that decides practicality. No target interaction.
python - <<'LATTICEANDADVA123D_CLASS1'
from math import log2  # lattice-and-advanced-crypto-attacks: class 1 leak inventory
for n_bits, leak_bits in ((1024, 512), (2048, 128), (2048, 512), (4096, 64)):
    bound = n_bits / 2          # degree-2 small root bound ~ N^(1/2)
    print(f"N={n_bits:>5} leak={leak_bits:>4} bound=2^{bound:>6.0f} practical={leak_bits >= bound}")
LATTICEANDADVA123D_CLASS1
```

Expected differential: `practical=True` only where the leak reaches the bound. That boolean, with the numbers, is the whole severity argument.

## Class 2 — Shared-high-bits probe

```text
# Do two moduli share a high half? A GCD settles it without any lattice.
python - <<'LATTICEANDADVA123D_CLASS2'
from math import gcd  # lattice-and-advanced-crypto-attacks: class 2 sharedhighbits probe
n1, n2 = (int(x) for x in open("moduli.txt").read().split()[:2])
g = gcd(n1, n2)  # lattice-and-advanced-crypto-attacks: class 2 sharedhighbits probe
print("shared factor:", g if 1 < g < n1 else "none", "bits:", g.bit_length() if g > 1 else 0)
LATTICEANDADVA123D_CLASS2
```

Expected differential: a non-trivial GCD is an immediate factorisation and belongs to the factorization skill; a near-miss (shared high bits, different factors) is the lattice case.

## Class 3 — Nonce-bias measurement

```text
# Measure the bit-length distribution of r-derived nonce hints across signatures.
python - <<'LATTICEANDADVA123D_CLASS3'
import json, statistics  # lattice-and-advanced-crypto-attacks: class 3 noncebias measurement
rs = [json.loads(l)["r"] for l in open("signatures.jsonl")]
bits = [int(r, 16).bit_length() for r in rs]
print("min/median/max bits:", min(bits), statistics.median(bits), max(bits))
LATTICEANDADVA123D_CLASS3
```

Expected differential: uniform nonces produce a tight distribution near the group order's bit length; a cluster of short values is the bias the hidden-number lattice consumes.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
