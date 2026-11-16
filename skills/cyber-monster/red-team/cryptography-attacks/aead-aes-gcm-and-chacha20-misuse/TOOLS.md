# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`aead-aes-gcm-and-chacha20-misuse`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool / surface | Command or entry point | What it settles | Platform |
|---|---|---|---|
| `cryptography` | `python -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM; print(AESGCM.generate_key(256).hex())"` | Confirms the library version exposes AEAD at all and the key width in use | CPython 3.8+ |
| `openssl` | `openssl enc -aes-256-gcm -K <hex> -iv <hex> -in p.txt` | Shows whether the CLI path even supports GCM tags (it truncates; do not use it as a reference) | POSIX, OpenSSL 3.x |
| `bssl` | `bssl client -connect host:443 -curves X25519MLKEM768` | Confirms the TLS terminator's AEAD/key-exchange pair, which changes the nonce budget in practice | BoringSSL build |
| `go` | `go doc crypto/cipher.NewGCMWithNonceSize` | Reads the exact nonce/overhead contract the Go path enforces | Go 1.21+ |
| `nuclei`-free check | `rg -n "tagLength\s*:\s*[0-9]+" web/` | Locates WebCrypto tag sizes without leaving the repo | any |
| `semgrep` | `semgrep --config p/cryptography --metrics=off src/` | Flags static-IV and weak-mode call sites as a first pass, not as proof | any |

## Minimal script shape

```python
# Report the AEAD parameter set for every call site in a repo, without touching it.
import re
import sys
import pathlib

PATTERNS = {
    "nonce_random": re.compile(r"urandom\(12\)|randomBytes\(12\)|NonceSize"),
    "aad_missing": re.compile(r"associated_data\s*=\s*None"),
    "tag_sliced": re.compile(r"\[:-?(12|8|4)\]"),
}

def scan(root: str) -> int:
    hits = 0
    for path in pathlib.Path(root).rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for name, pat in PATTERNS.items():
            for m in pat.finditer(text):
                line = text[: m.start()].count("
") + 1
                print(f"{path}:{line}: {name}")
                hits += 1
    return hits

if __name__ == "__main__":
    sys.exit(0 if scan(sys.argv[1]) == 0 else 1)
```

Run it against the repo root; a non-zero exit means a parameter needs a human read, not that a vulnerability exists.
