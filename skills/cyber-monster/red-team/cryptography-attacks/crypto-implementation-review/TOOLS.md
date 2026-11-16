# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`crypto-implementation-review`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `rg` | `rg -n -e 'sha1\(' -e 'sha256\(' -g '!test*'` | Concatenation MACs, the highest-yield single pattern in this review | any |
| `bandit` | `bandit -r . -t B303,B304,B105,B106 -q` | Weak-hash and hardcoded-password findings as a triage list, not as proof | CPython |
| `semgrep` | `semgrep --config p/secrets --config p/cryptography --metrics=off .` | Key literals and risky call shapes across languages | any |
| `trufflehog` | `trufflehog filesystem . --only-verified --no-update` | Confirms a candidate key literal against the provider, which separates a fixture from a live secret | any |
| `openssl` | `openssl dgst -sha256 -hmac <key> -in body.bin` | Reproduces the MAC offline so the token arithmetic is verifiable | OpenSSL 3.x |

## Minimal script shape

```python
# Composition inventory: every construction, its primitives, and its framing.
import pathlib
import re

PATTERNS = {
    "concat_mac": re.compile(r"(sha1|sha256|md5)\(\s*(key|secret)\s*\+"),
    "hmac": re.compile(r"hmac\.new|createHmac|HMAC\("),
    "no_iv": re.compile(r"modes\.CBC\(\)|MODE_CBC\)"),
    "kdf": re.compile(r"pbkdf2_hmac|scrypt|argon2"),
}

def inventory(root: str) -> dict:
    found = {k: [] for k in PATTERNS}
    for p in pathlib.Path(root).rglob("*.py"):
        text = p.read_text(errors="ignore")
        for name, pat in PATTERNS.items():
            for m in pat.finditer(text):
                found[name].append(f"{p}:{text[:m.start()].count(chr(10)) + 1}")
    return found

if __name__ == "__main__":
    for k, v in inventory(".").items():
        print(f"{k:>10}: {len(v)}")
```

The `concat_mac` list is the finding queue; the `hmac` list is where those sites should move.
