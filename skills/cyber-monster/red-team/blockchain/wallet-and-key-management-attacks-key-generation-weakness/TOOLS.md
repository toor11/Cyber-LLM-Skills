# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`wallet-and-key-management-attacks-key-generation-weakness`](SKILL.md) | Family: **Blockchain**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** `secrets` or the platform keystore for entropy, BIP-32/39 derivation, and RFC 6979 deterministic ECDSA for signing.
- **Validation Gate:** one test that two distinct messages produce different `r` values, and one that the key source is the CSPRNG.
- Python's `random` module is not a CSPRNG; `secrets` is the correct source for key material.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `python` | `python -c "import secrets; print(len(secrets.token_bytes(32)))"` | Confirm the CSPRNG interface available | Cross-platform |
| `openssl` | `openssl rand -hex 32` | Independent CSPRNG for a comparison value | Cross-platform |
| `cast` | `cast wallet new` | Generate a test key without touching production material | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import hashlib
import secrets

from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigencode_string

seed = int.from_bytes(secrets.token_bytes(32), "big")
sk = SigningKey.from_secret_exponent(seed, curve=SECP256k1)
a = sk.sign_deterministic(b"transfer:1", hashfunc=hashlib.sha256, sigencode=sigencode_string)
b = sk.sign_deterministic(b"transfer:2", hashfunc=hashlib.sha256, sigencode=sigencode_string)
print("nonce differs:", a[:32] != b[:32])
```
