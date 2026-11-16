# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`lattice-and-advanced-crypto-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `sage` | `sage -c "N=...; P.<x>=PolynomialRing(Zmod(N)); print(x.small_roots(X=2^512))"` | The small-root solve, and whether the bound is met | SageMath |
| `fpylll` | `python -c "from fpylll import IntegerMatrix, LLL; print(LLL)"` | Confirms lattice reduction is available for a scripted bound check | CPython with fpylll |
| `python` | `python -c "from math import gcd; print(gcd(2**64-1, 2**32-1))"` | Fast shared-factor check before any lattice work | CPython |
| `openssl` | `openssl rsa -in key.pem -text -noout` | Key parameters, bit lengths, and exponent, as the input to bound arithmetic | OpenSSL 3.x |
| `pari` | `gp -q <<< "factor(123456789012345678901234567890)"` | Independent factorisation for small cases | PARI/GP |

## Minimal script shape

```python
# Decide whether a partial-factor leak is practical, and emit the arithmetic.
from dataclasses import dataclass

@dataclass
class Leak:
    n_bits: int
    leak_bits: int
    degree: int = 2

    @property
    def bound_bits(self) -> float:
        return self.n_bits / self.degree

    @property
    def practical(self) -> bool:
        return self.leak_bits >= self.bound_bits

    @property
    def margin_bits(self) -> float:
        return self.bound_bits - self.leak_bits

if __name__ == "__main__":
    for case in (Leak(1024, 512), Leak(2048, 128), Leak(4096, 64)):
        print(case, "margin=%.0f bits" % case.margin_bits)
```

A positive margin means no lattice is needed to close the finding; a non-positive margin means the leak meets the bound and the severity is real.
