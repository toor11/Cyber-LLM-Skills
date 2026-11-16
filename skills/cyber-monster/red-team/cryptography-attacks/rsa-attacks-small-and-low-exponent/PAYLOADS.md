# Verification Probes and Expected Differentials

> Sub-skill: [`rsa-attacks-small-and-low-exponent`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Exponent and padding inventory

```text
# e and padding per encryption call site.
rg -n --no-heading "public_exponent|65537|exponent=3|\be\s*=\s*3\b|NoPadding|OAEP|PKCS1v15" -g '!test*'
```

Expected differential: `e=3` with `NoPadding` or a raw `pow` is the finding; `e=3` with OAEP, or `e=65537` with any padding, is a control.

## Class 2 — Integer-root probe (offline)

```text
# Is the ciphertext an exact cube? Offline, on lab values only.
python - <<'RSAATTACKSSMAL2CD2_CLASS2'
from math import isqrt  # rsa-attacks-small-and-low-exponent: class 2 integerroot probe
def iroot3(x: int) -> int:
    lo, hi = 0, 1 << ((x.bit_length() // 3) + 2)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** 3 < x: lo = mid + 1
        else: hi = mid
    return lo
c = int.from_bytes(open("ct.bin","rb").read(), "big")
r = iroot3(c)
print("exact cube:", r ** 3 == c, "root bytes:", r.to_bytes((r.bit_length()+7)//8, "big")[:16])
RSAATTACKSSMAL2CD2_CLASS2
```

Expected differential: `exact cube: True` with structured root bytes is the finding; `False` means the message exceeded the no-reduction bound or padding was applied.

## Class 3 — Hastad precondition

```text
# Same plaintext to N recipients: CRT then one root. Count matching ciphertext sizes.
python - <<'RSAATTACKSSMAL2CD2_CLASS3'
import pathlib, collections
sizes = collections.Counter(p.stat().st_size for p in pathlib.Path("recipients").glob("*.bin"))
print(sizes)   # >= 3 equal sizes under e=3 is the Hastad candidate
RSAATTACKSSMAL2CD2_CLASS3
```

Expected differential: three or more equal-length ciphertexts under `e=3` is the precondition; a single recipient means only the single-root branch applies.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
