# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`symmetric-cipher-attacks-keystream-and-nonce-reuse`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `xxd` | `xxd -g1 -l 12 ct/a.bin` | The nonce prefix, which is the grouping key | POSIX |
| `python` | `python -c "a=open('a','rb').read();b=open('b','rb').read();print(bytes(x^y for x,y in zip(a,b)).hex()[:64])"` | The XOR differential without any dependencies | CPython |
| `openssl` | `openssl enc -aes-256-ctr -K <hex> -iv <hex> -in p.txt` | Reproduces keystream arithmetic for a lab key | OpenSSL 3.x |
| `ent` | `ent xor.bin` | Entropy of the XOR result; low entropy indicates structure | POSIX |
| `rg` | `rg -n "nonce\s*=\s*b?[\"']"` | Literal nonces in code, the most severe form | any |

## Minimal script shape

```python
# Find keystream reuse and score the resulting differential for structure.
import collections
import pathlib
import string

NONCE = 12

def groups(root: str) -> dict[str, list[pathlib.Path]]:
    out = collections.defaultdict(list)
    for p in pathlib.Path(root).glob("*.bin"):
        raw = p.read_bytes()
        out[raw[:NONCE].hex()].append(p)
    return {k: v for k, v in out.items() if len(v) > 1}

def structure(x: bytes) -> float:
    return sum(chr(c) in string.printable for c in x) / max(len(x), 1)

if __name__ == "__main__":
    for nonce, paths in groups("ct").items():
        a, b = (p.read_bytes()[NONCE:] for p in paths[:2])
        x = bytes(p ^ q for p, q in zip(a, b))
        print(nonce, "pairs:", len(paths), "structure:", round(structure(x), 2))
```

A `structure` value near 1.0 on a reused-nonce pair is the finding; distinct nonces produce values near the random baseline.
