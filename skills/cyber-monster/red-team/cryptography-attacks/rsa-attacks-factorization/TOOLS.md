# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`rsa-attacks-factorization`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `openssl` | `openssl x509 -in c.pem -noout -modulus` | Modulus extraction for the GCD sweep | OpenSSL 3.x |
| `openssl` | `openssl rsa -in k.pem -text -noout` | Prime count and sizes, which identifies multi-prime keys | OpenSSL 3.x |
| `python` | `python -c "from math import gcd,isqrt; print(gcd(2**64-1,2**32-1))"` | The two cheapest checks, without dependencies | CPython |
| `pari` | `gp -q <<< "factorint(123456789012345678901)"` | General factoring for small moduli, with a method trail | PARI/GP |
| `yafu` | `yafu "factor(123456789012345678901234567890)"` | Fermat and ECM on a lab modulus with timing | assessment hosts |

## Minimal script shape

```python
# Bounded factorisation triage: each method reports the bound it used.
import itertools
from math import gcd, isqrt

def pairwise(mods: dict[str, int]) -> list[tuple[str, str, int]]:
    out = []
    for (a, n1), (b, n2) in itertools.combinations(mods.items(), 2):
        g = gcd(n1, n2)
        if 1 < g < min(n1, n2):
            out.append((a, b, g))
    return out

def fermat(n: int, limit: int = 200_000) -> tuple[int, int] | None:
    a = isqrt(n)
    for i in range(limit):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return a - b, i
        a += 1
    return None

def pollard_pm1(n: int, bound: int = 100_000) -> int | None:
    a = 2
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        e = 1
        while p ** (e + 1) <= bound:
            e += 1
        a = pow(a, p ** e, n)
    d = gcd(a - 1, n)
    return d if 1 < d < n else None
```

Every method carries its bound, so the report can state "not factored within 2e5 Fermat iterations and B=1e5 Pollard" rather than "could not factor".
