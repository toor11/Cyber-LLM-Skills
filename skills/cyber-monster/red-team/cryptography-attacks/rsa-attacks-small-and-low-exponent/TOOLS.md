# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`rsa-attacks-small-and-low-exponent`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `openssl` | `openssl rsa -pubin -in k.pem -text -noout` | The exponent, read from the key rather than the code | OpenSSL 3.x |
| `python` | `python -c "from sympy import integer_nthroot; print(integer_nthroot(27,3))"` | Exact integer root with a correctness check | CPython with sympy |
| `sage` | `sage -c "print(Mod(1234567, 10^9).nth_root(3))"` | Root over a modulus, for the padded variant | SageMath |
| `rg` | `rg -n -e NoPadding -e 'pow\\('` | Raw exponentiation sites | any |
| `rsactftool` | `python RsaCtfTool.py --publickey k.pem --uncipherfile c.bin --attack cube_root` | Lab-only confirmation of the branch | assessment hosts |

## Minimal script shape

```python
# Decide which small-exponent branch applies, from public parameters only.
from dataclasses import dataclass

@dataclass
class SmallExp:
    e: int
    n_bits: int
    msg_bits: int
    padding: str
    recipients: int = 1

    @property
    def no_reduction(self) -> bool:
        return self.msg_bits * self.e < self.n_bits and self.padding == "none"

    @property
    def hastad(self) -> bool:
        return self.e == 3 and self.padding == "none" and self.recipients >= 3

    def branches(self) -> list[str]:
        out = []
        if self.no_reduction: out.append("integer_root")
        if self.hastad: out.append("hastad")
        if self.padding.startswith("fixed") and self.e == 3: out.append("coppersmith")
        return out or ["none"]

if __name__ == "__main__":
    print(SmallExp(3, 2048, 128, "none", 3).branches())
    print(SmallExp(3, 2048, 128, "oaep", 3).branches())
```

The first line names the branches to pursue; the second demonstrates that randomisation closes them all.
