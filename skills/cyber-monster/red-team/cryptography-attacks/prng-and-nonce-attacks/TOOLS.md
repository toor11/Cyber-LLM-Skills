# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`prng-and-nonce-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `python` | `python -c "import random; random.seed(0); print([random.getrandbits(32) for _ in range(3)])"` | Reproduces MT19937 determinism for a known seed, proving the state is the only mystery | CPython |
| `rg` | `rg -n -e 'random\.' -e 'mt_rand' -e 'Math\.random'` | Generator inventory across a codebase | any |
| `dieharder` | `dieharder -a -g 500 -f stream.bin` | Statistical quality of a captured stream, as supporting evidence only | POSIX |
| `ent` | `ent stream.bin` | Entropy estimate and serial correlation of a byte stream | POSIX |
| `python` | `python -c "import secrets; print(secrets.token_urlsafe(32))"` | The control value shape for comparison | CPython 3.6+ |

## Minimal script shape

```python
# Generator risk classifier over a source tree. Static, no execution.
import pathlib
import re

WEAK = re.compile(r"\brandom\.(?:random|randint|choice|getrandbits|shuffle)\b|"
                  r"Math\.random|new\s+Random\(|mt_rand|(?<!s)\brand\(\)")
STRONG = re.compile(r"secrets\.|os\.urandom|getrandom|SecureRandom|rand_bytes")

def classify(root: str) -> dict:
    hits = {"weak": [], "strong": []}
    for p in pathlib.Path(root).rglob("*.py"):
        t = p.read_text(errors="ignore")
        for kind, pat in (("weak", WEAK), ("strong", STRONG)):
            for m in pat.finditer(t):
                hits[kind].append(f"{p}:{t[:m.start()].count(chr(10)) + 1}:{m.group(0)}")
    return hits

if __name__ == "__main__":
    h = classify(".")
    print("weak:", len(h["weak"]), "strong:", len(h["strong"]))
    for w in h["weak"][:10]:
        print("  ", w)
```

A `weak` hit in a module that also builds tokens or keys is the finding; a `weak` hit in a sampling or jitter helper is not.
