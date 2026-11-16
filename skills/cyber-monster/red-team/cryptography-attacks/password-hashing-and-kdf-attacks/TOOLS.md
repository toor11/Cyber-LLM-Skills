# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`password-hashing-and-kdf-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `argon2` | `echo -n pw` | Parameter behaviour and encoded output format | argon2 CLI |
| `htpasswd` | `htpasswd -bnBC 12 "" pw` | bcrypt cost 12 output shape, for comparing a stored prefix | Apache utils |
| `python` | `python -c "import bcrypt;print(bcrypt.gensalt(rounds=12))"` | The salt/cost encoding a current library produces | CPython with bcrypt |
| `hashcat` | `hashcat -b -m 3200` | Measured bcrypt rate on the assessment GPU, which is the attacker's per-guess cost | hashcat |
| `rg` | `rg -n -e 'sha256\\(.*password' -e 'md5\\(.*pass'` | Fast-hash password sites | any |

## Minimal script shape

```python
# Parse stored formats and flag anything below the current floor.
import collections
import re
from dataclasses import dataclass

BCRYPT = re.compile(r"^\$2[aby]\$(\d\d)\$")
ARGON2 = re.compile(r"^\$argon2id\$v=\d+\$m=(\d+),t=(\d+),p=(\d+)\$")

@dataclass
class Floor:
    bcrypt_cost: int = 12
    argon2_mib: int = 19

def audit(path: str, floor: Floor = Floor()) -> dict:
    weak = collections.Counter()
    total = 0
    for line in open(path):
        h = line.strip()
        total += 1
        m = BCRYPT.match(h)
        if m and int(m.group(1)) < floor.bcrypt_cost:
            weak["bcrypt_low"] += 1
            continue
        m = ARGON2.match(h)
        if m and int(m.group(1)) // 1024 < floor.argon2_mib:
            weak["argon2_low_mem"] += 1
            continue
        if re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{64}", h):
            weak["unsalted_fast"] += 1
    return {"total": total, "weak": dict(weak)}

if __name__ == "__main__":
    print(audit("hashes.txt"))
```

Any non-empty `weak` map is the finding, and the counts size the exposure so the remediation plan can be staged.
