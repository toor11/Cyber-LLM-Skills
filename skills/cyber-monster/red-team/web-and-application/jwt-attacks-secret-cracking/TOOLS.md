# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`jwt-attacks-secret-cracking`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `hashcat` | `hashcat -m 16500 token.txt wordlist.txt` | Recover a weak HS256/384/512 secret offline from one captured token | Linux, Windows, macOS |
| `John the Ripper` | `john --format=HMAC-SHA256 --wordlist=rockyou.txt token.txt` | Alternative offline dictionary recovery of the HMAC secret | Cross-platform |
| `jwt_tool` | `python3 jwt_tool.py <token> -C -d wordlist.txt` | Dictionary-crack the signing secret and confirm by signature equality | Cross-platform |

## Minimal Script Shape

An entropy estimator that scores a candidate HMAC secret and reports whether it is weak enough to be offline-crackable, used to triage before any cracking run.

```python
import math, sys
from collections import Counter

def shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())

def assess(secret_guess: str) -> str:
    bits = shannon(secret_guess) * len(secret_guess)
    if len(secret_guess) < 16 or bits < 64:
        return "weak - offline crackable (est bits=%.1f)" % bits
    return "strong - offline crack infeasible (est bits=%.1f)" % bits

for guess in sys.argv[1:]:
    print(repr(guess), "->", assess(guess))
```
