# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`rsa-attacks-signature-forgery`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `openssl` | `openssl dgst -sha256 -verify pub.pem -signature sig.bin msg.bin` | Reference verification for comparison with the application's | OpenSSL 3.x |
| `openssl` | `openssl pkeyutl -verifyrecover -pubin -inkey pub.pem -in sig.bin` | The recovered encoding, which shows exactly what the verifier sees | OpenSSL 3.x |
| `python` | `python -c "print(pow(2,3,1<<2048).bit_length())"` | Modexp arithmetic for the accepted-region calculation | CPython |
| `rg` | `rg -n "pow\\(.*, *e, *n\\)"` | Hand-rolled verification sites | any |
| `asn1parse` | `openssl asn1parse -inform DER -in enc.bin` | Whether the encoding parses strictly or tolerates trailing bytes | OpenSSL 3.x |

## Minimal script shape

```python
# Report the accepted region of a signature verifier from its comparison shape.
from dataclasses import dataclass

@dataclass
class Verifier:
    name: str
    checks_full_block: bool
    checks_prefix_bytes: int
    accepts_short: bool
    e: int

    @property
    def unconstrained_bits(self) -> int:
        if self.checks_full_block:
            return 0
        return 2048 - self.checks_prefix_bytes * 8

    @property
    def constructible(self) -> bool:
        return self.unconstrained_bits > 0 and self.e <= 3

if __name__ == "__main__":
    for v in (Verifier("library", True, 256, False, 3),
              Verifier("prefix8", False, 8, False, 3),
              Verifier("prefix8_e65537", False, 8, False, 65537)):
        print(v, "unconstrained:", v.unconstrained_bits, "constructible:", v.constructible)
```

`constructible: True` is the finding and it comes with the exponent in the same line, which makes the severity argument self-contained.
