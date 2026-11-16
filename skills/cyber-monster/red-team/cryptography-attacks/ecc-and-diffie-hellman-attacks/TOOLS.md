# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`ecc-and-diffie-hellman-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `openssl` | `openssl ecparam -name prime256v1 -text -noout` | The exact group parameters in use, including the order and cofactor | OpenSSL 3.x |
| `openssl` | `openssl pkey -pubin -in peer.der -text -noout` | Whether a supplied key parses into the expected curve | OpenSSL 3.x |
| `python` | `python -c "from cryptography.hazmat.primitives.asymmetric import ec; print(ec.SECP256R1().key_size)"` | The claimed strength of the configured curve | CPython 3.8+ |
| `sage`/`pari` | `sage -c "E = EllipticCurve(GF(p), [a,b]); print(E.order().factor())"` | Group order and its factorisation, which is what a subgroup argument rests on | SageMath |
| `rg` | `rg -n -e 'exchange\(' -e compute_key -e ECDH -g '!test*'` | Every point-exchange call site, the entry point for the audit | any |

## Minimal script shape

```python
# Verify the validation contract of a library path without touching a peer.
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

def contract_ok(der: bytes, expect=ec.SECP256R1) -> tuple[bool, str]:
    try:
        key = serialization.load_der_public_key(der)
    except Exception as exc:
        return False, f"decode rejected: {type(exc).__name__}"
    if not isinstance(key, ec.EllipticCurvePublicKey):
        return False, "not an EC public key"
    if not isinstance(key.curve, expect):
        return False, f"wrong group {type(key.curve).__name__}"
    return True, "on-curve, expected group"

if __name__ == "__main__":
    print(contract_ok(open("peer.der", "rb").read()))
```

A `False` with a decode rejection is a control; a `True` on a point you know is off-curve is the finding.
