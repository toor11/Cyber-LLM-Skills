# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`classical-and-covert-encoding`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `file` | `file --mime-type artifact.bin` | Carrier type from magic bytes, not extension | POSIX |
| `base64` | `base64 -d artifact.b64` | First bytes of the decoded payload, which is where the magic number is | coreutils |
| `binwalk` | `binwalk artifact.bin` | Embedded signatures and appended regions in one pass | POSIX, needs install |
| `xxd` | `xxd -g1 -s -256 artifact.bin` | The tail, where appended data lives | POSIX |
| `python` | `python -c "import unicodedata,sys;print([hex(ord(c)) for c in open(sys.argv[1],encoding='utf-8').read() if unicodedata.category(c)=='Cf'])" f.txt` | Enumerates zero-width carriers in a text field | CPython 3.8+ |

## Minimal script shape

```python
# Identify the transform and report the payload region, without extracting anything.
import base64
import binascii
import pathlib
import string

CANDIDATES = {"b64": base64.b64decode, "b32": base64.b32decode,
              "b16": binascii.unhexlify}
PRINTABLE = set(bytes(string.printable, "ascii"))

def describe(path: str) -> dict:
    raw = pathlib.Path(path).read_bytes()
    out = {"path": path, "bytes": len(raw), "head": raw[:8].hex()}
    for name, fn in CANDIDATES.items():
        try:
            dec = fn(raw.strip() + b"=" * (-len(raw.strip()) % 4))
        except Exception:
            continue
        out[name] = {"len": len(dec),
                     "printable": round(sum(b in PRINTABLE for b in dec) / max(len(dec), 1), 2)}
    return out

if __name__ == "__main__":
    print(describe("artifact.b64"))
```

Report the winning transform and the decoded length; do not print decoded content unless the sample is authorised for disclosure.
