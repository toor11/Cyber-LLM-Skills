# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`block-cipher-modes-and-padding-oracles`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `openssl` | `openssl enc -aes-128-cbc -K <hex> -iv <hex> -in p.txt -out c.bin` | Reproduces the exact block arithmetic the service performs, offline | OpenSSL 3.x |
| `xxd` | `xxd -g1 -c16 c.bin` | Aligns ciphertext on 16-byte boundaries so block indices are unambiguous | any POSIX |
| `python` | `python -c "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes; print(Cipher(algorithms.AES(b'0'*16), modes.ECB()))"` | Confirms the library still offers the mode you suspect | CPython 3.8+ |
| `jq` | `jq -r '.ciphertext' resp.json` | Decodes API responses into blocks without writing a script | any |
| `time`/`hyperfine` | `hyperfine --warmup 50 --runs 500 'curl -s -X POST .../decrypt'` | Separates a real timing oracle from network jitter | any |

## Minimal script shape

```python
# Block-indexed view of a ciphertext, so every probe refers to the same coordinates.
import sys
import base64

def blocks(blob: bytes, size: int = 16):
    usable = len(blob) - (len(blob) % size)
    return [blob[i:i + size] for i in range(0, usable, size)]

def main(path: str) -> int:
    raw = open(path, "rb").read()
    for i, b in enumerate(blocks(raw)):
        print(f"block {i:>3} {b.hex()}")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
```

Pipe a base64 response through `base64 -d` into this to get block indices you can cite in the finding.
