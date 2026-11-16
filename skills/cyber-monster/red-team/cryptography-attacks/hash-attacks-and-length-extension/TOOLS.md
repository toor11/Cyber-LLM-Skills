# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`hash-attacks-and-length-extension`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `hashpump` | `hashpump -s <sig> -d 'orig' -a '&role=admin' -k 16` | Computes the extended message and digest for a given secret length | POSIX, needs install |
| `python` | `python -c "import hmac,hashlib;print(hmac.new(b'k',b'm','sha256').hexdigest())"` | Produces the correct construction's value for comparison | CPython 3.8+ |
| `openssl` | `openssl dgst -sha256 -mac HMAC -macopt hexkey:00ff data.bin` | Independent HMAC computation to confirm the verifier's arithmetic | OpenSSL 3.x |
| `rg` | `rg -n -e 'sha1\(' -e 'sha256\('` | Finds the concatenation construction across languages | any |
| `hashdeep`/`sha256sum` | `sha256sum --check manifest.txt` | Reproduces an integrity check to see whether the digest is the control | coreutils |

## Minimal script shape

```python
# Classify a MAC construction and report whether extension applies.
import re
import pathlib

CONCAT = re.compile(r"(sha1|sha256|sha512|md5)\(\s*([a-zA-Z_]*(?:secret|key)[a-zA-Z_]*)\s*\+")
HMAC = re.compile(r"hmac\.new|createHmac|HMAC\(")

def classify(root: str) -> dict:
    out = {"concat": [], "hmac": []}
    for p in pathlib.Path(root).rglob("*.py"):
        t = p.read_text(errors="ignore")
        out["concat"] += [f"{p}:{t[:m.start()].count(chr(10)) + 1}" for m in CONCAT.finditer(t)]
        out["hmac"] += [f"{p}:{t[:m.start()].count(chr(10)) + 1}" for m in HMAC.finditer(t)]
    out["extendable"] = bool(out["concat"])
    return out

if __name__ == "__main__":
    print(classify("."))
```

Any `concat` hit with no `hmac` hit in the same module is the finding; report the secret length you assumed so the proof is reproducible.
