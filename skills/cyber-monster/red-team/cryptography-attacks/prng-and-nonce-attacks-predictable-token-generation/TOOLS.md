# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`prng-and-nonce-attacks-predictable-token-generation`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `curl` | `curl -s -o /dev/null -w '%{http_code}' -X POST $API/reset/redeem -d "user=u&token=t"` | Binding and replay behaviour in two requests | any |
| `python` | `python -c "import math;print(2**math.log2(10**6))"` | The space arithmetic you cite | CPython |
| `rg` | `rg -n -e 'uuid1\(' -e 'random\.randint' -e 'randrange'` | Token-format provenance in code | any |
| `siege`/`vegeta` | `echo "POST $API/reset/redeem"` | Whether a rate limit exists at all | any |
| `sqlite3` | `sqlite3 app.db "select count(*), count(distinct token_hash) from reset;"` | Duplicate or colliding tokens in the store | sqlite3 |

## Minimal script shape

```python
# Token-space and budget comparison; the ratio decides the finding.
import math
from dataclasses import dataclass

@dataclass
class TokenProfile:
    alphabet: int
    length: int
    predictable_bits: int = 0
    attempts_per_token: int = 5

    @property
    def space_bits(self) -> float:
        return math.log2(self.alphabet ** self.length) - self.predictable_bits

    @property
    def online_feasible(self) -> bool:
        return self.space_bits - math.log2(self.attempts_per_token) < 40

if __name__ == "__main__":
    for p in (TokenProfile(10, 6), TokenProfile(32, 8), TokenProfile(64, 43)):
        print(p, round(p.space_bits, 1), p.online_feasible)
```

An `online_feasible: True` with a documented attempt limit is the quantified finding; `False` with binding and single use present is the control.
