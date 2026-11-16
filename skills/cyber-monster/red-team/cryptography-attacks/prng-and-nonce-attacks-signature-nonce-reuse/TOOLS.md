# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`prng-and-nonce-attacks-signature-nonce-reuse`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `openssl` | `openssl asn1parse -in sig.der -inform DER` | Extracts `r` and `s` from a DER signature without a script | OpenSSL 3.x |
| `python` | `python -c "from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature as d; print(d(open('sig.der','rb').read()))"` | The same values as integers, ready for comparison | CPython with `cryptography` |
| `sage` | `sage -c "n=...; print((s1*z2 - s2*z1) * inverse_mod(r*(s1-s2), n) % n)"` | The two-equation solve, on lab values only | SageMath |
| `rg` | `rg -n "sign_digest\(.*k="` | Call sites that inject a nonce, which is the highest-risk pattern | any |
| `fpylll` | `python -c "from fpylll import IntegerMatrix; print('ok')"` | Confirms lattice tooling for the bias branch | CPython with fpylll |

## Minimal script shape

```python
# Repeated-nonce detector over published signatures; read-only and offline.
import collections
import json
import sys
from dataclasses import dataclass

@dataclass
class Sig:
    r: int
    s: int
    z: int

def load(path: str) -> list[Sig]:
    return [Sig(int(d["r"], 16), int(d["s"], 16), int(d["z"], 16))
            for d in map(json.loads, open(path))]

def repeats(sigs: list[Sig]) -> dict[int, set[int]]:
    by_r = collections.defaultdict(set)
    for x in sigs:
        by_r[x.r].add(x.z)
    return {r: zs for r, zs in by_r.items() if len(zs) > 1}

if __name__ == "__main__":
    found = repeats(load("sigs.jsonl"))
    print(f"{len(found)} repeated-nonce groups")
    sys.exit(0 if not found else 1)
```

A non-zero exit means at least one key is recoverable from public data; report the group sizes and the remediation, and do not compute the key.
