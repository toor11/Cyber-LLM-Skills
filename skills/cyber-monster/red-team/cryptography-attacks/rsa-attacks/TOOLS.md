# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`rsa-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `openssl` | `openssl rsa -pubin -in k.pem -text -noout` | Modulus and exponent, the input to every branch decision | OpenSSL 3.x |
| `openssl` | `openssl x509 -in c.pem -noout -modulus` | Compact modulus extraction for a GCD sweep | OpenSSL 3.x |
| `python` | `python -c "from math import gcd;print(gcd(15,21))"` | Confirms the shared-factor arithmetic before the sweep | CPython |
| `sage` | `sage -c "print(Integer(12345).nth_root(3))"` | Integer root for the small-exponent check | SageMath |
| `rsactftool` | `python RsaCtfTool.py --publickey k.pem --attack all` | Automated family triage on lab keys; never on production | assessment hosts |

## Minimal script shape

```python
# RSA parameter triage: which of the four families is even possible.
from dataclasses import dataclass

@dataclass
class Params:
    n_bits: int
    e: int
    padding: str
    constant_time: bool

    def families(self) -> list[str]:
        out = []
        if self.n_bits < 2048:
            out.append("strength")
        if self.e <= 3:
            out.append("small_exponent")
        if self.padding.lower().startswith("pkcs1") and not self.constant_time:
            out.append("padding_oracle")
        if self.padding.lower() == "none":
            out.append("raw_unpadded")
        return out or ["none_of_these"]

if __name__ == "__main__":
    print(Params(1024, 3, "pkcs1v15", False).families())
    print(Params(2048, 65537, "oaep", True).families())
```

The first line names the families to pursue; `none_of_these` is the disposition you record with the parameters.
