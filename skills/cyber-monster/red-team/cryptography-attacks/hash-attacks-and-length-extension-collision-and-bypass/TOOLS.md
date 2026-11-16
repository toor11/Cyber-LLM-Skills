# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`hash-attacks-and-length-extension-collision-and-bypass`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `php` | `php -r 'var_dump("0e1" == "0e2");'` | Whether the runtime coerces digest-shaped strings | PHP 7/8 |
| `python` | `python -c "print('0e1' == '0e2')"` | The Python comparison semantics for the same inputs, which differ by design | CPython |
| `rg` | `rg -n -e '==\\s*\\$?stored' -e '==\\s*\\$?expected'` | Loose comparisons across a codebase | any |
| `openssl` | `openssl dgst -md5 collide_a.bin collide_b.bin` | Confirms two files share an MD5 without trusting your own code | OpenSSL 3.x |
| `hashcat` | `hashcat --example-hashes` | Mode numbers for any offline work on truncated values | any |

## Minimal script shape

```python
# Classify comparison sites by coercion risk and truncation width.
import pathlib
import re

LOOSE = re.compile(r"(md5|sha1)\([^)]*\)\s*==|==\s*(stored|expected)")
STRICT = re.compile(r"hash_equals|compare_digest|===|ConstantTimeCompare")
TRUNC = re.compile(r"\[:\s*(\d{1,2})\]|substr\([^,]+,\s*0\s*,\s*(\d{1,2})\)")

def classify(root: str) -> dict:
    out = {"loose": [], "strict": [], "truncated": []}
    for p in pathlib.Path(root).rglob("*"):
        if p.suffix not in (".php", ".py", ".js", ".go", ".java"):
            continue
        t = p.read_text(errors="ignore")
        for name, pat in (("loose", LOOSE), ("strict", STRICT), ("truncated", TRUNC)):
            out[name] += [f"{p}:{t[:m.start()].count(chr(10)) + 1}" for m in pat.finditer(t)]
    return out

if __name__ == "__main__":
    for k, v in classify(".").items():
        print(f"{k:>10}: {len(v)}")
```

A `loose` hit with no `strict` hit in the same file is the finding; a `truncated` hit gets a width calculation before it gets a severity.
