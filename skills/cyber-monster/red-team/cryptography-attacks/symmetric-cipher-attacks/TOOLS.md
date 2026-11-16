# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`symmetric-cipher-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `openssl` | `openssl enc -aes-256-ctr -K <hex> -iv <hex> -in p.txt` | Reproduces CTR keystream arithmetic offline | OpenSSL 3.x |
| `xxd` | `xxd -g1 -l 32 c.bin` | Compares nonce prefixes across two ciphertexts | POSIX |
| `rg` | `rg -n -e 'MODE_CTR' -e 'MODE_OFB' -e 'MODE_CFB' -e 'Counter\.new'` | Stream-mode call sites, the entry point for the audit | any |
| `python` | `python -c "from Crypto.Util import Counter; print(Counter.new(128))"` | The counter object's default start value, which is the reset defect | PyCryptodome |
| `systemd-analyze` | `systemctl show app -p ExecMainStartTimestamp` | Restart times, which bracket the nonce-reset windows | Linux services |

## Minimal script shape

```python
# Classify the nonce lifecycle of every stream-mode call site.
import pathlib
import re

RESET = re.compile(r"Counter\.new\(\s*128\s*\)|IvParameterSpec\(\s*new byte\[")
TIME = re.compile(r"time\.time\(\)|datetime\.now\(\)|System\.currentTimeMillis")
SAFE = re.compile(r"os\.urandom|secrets\.token_bytes|SecureRandom|nextval|sequence")

def classify(root: str) -> dict:
    out = {"reset": [], "time": [], "safe": []}
    for p in pathlib.Path(root).rglob("*"):
        if p.suffix not in (".py", ".java", ".go", ".js"):
            continue
        t = p.read_text(errors="ignore")
        for k, pat in (("reset", RESET), ("time", TIME), ("safe", SAFE)):
            out[k] += [f"{p}:{t[:m.start()].count(chr(10)) + 1}" for m in pat.finditer(t)]
    return out

if __name__ == "__main__":
    for k, v in classify(".").items():
        print(f"{k:>6}: {len(v)}")
```

A `reset` or `time` hit in a module with a stream-mode call is the finding; a `safe` hit in the same module is the control to cite.
