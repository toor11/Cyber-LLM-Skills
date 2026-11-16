# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`symmetric-cipher-attacks-weak-key-derivation`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `rg` | `rg -n -e 'KEY\\s*=' -e 'SECRET\\s*='` | Literal key inventory | any |
| `trufflehog` | `trufflehog filesystem . --only-verified --no-update` | Whether a candidate literal is a live credential | any |
| `python` | `python -c "import hashlib,time;t=time.perf_counter();[hashlib.sha256(b'x').digest() for _ in range(1000)];print(1000/(time.perf_counter()-t))"` | Derivation rate for the fast-hash case | CPython |
| `openssl` | `openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt pass:x -kdfopt salt:00 PBKDF2` | PBKDF2 parameters and output, for reproducing a deployment's derivation | OpenSSL 3.x |
| `vault` | `vault kv get -field=key secret/app` | Whether the key comes from a managed store rather than config | HashiCorp Vault CLI |

## Minimal script shape

```python
# Rank key origins by attack cost, using measured derivation rates.
import hashlib
import time
from dataclasses import dataclass

@dataclass
class Origin:
    kind: str                 # literal | hash | pbkdf2 | argon2 | kms
    entropy_bits: float
    seconds_per_guess: float

    @property
    def search_days(self) -> float:
        return (2 ** self.entropy_bits) * self.seconds_per_guess / 86400

def measure_sha256(n: int = 2000) -> float:
    t0 = time.perf_counter()
    for _ in range(n):
        hashlib.sha256(b"candidate").digest()
    return (time.perf_counter() - t0) / n

if __name__ == "__main__":
    rate = measure_sha256()
    for o in (Origin("literal", 0, rate), Origin("hash", 30, rate),
              Origin("argon2id", 30, 0.05), Origin("kms", 256, 0)):
        print(o.kind, "search_days=%.2e" % o.search_days)
```

A `literal` origin is a zero-entropy finding; the comparison between a fast hash and Argon2id at the same entropy is what justifies the KDF recommendation.
