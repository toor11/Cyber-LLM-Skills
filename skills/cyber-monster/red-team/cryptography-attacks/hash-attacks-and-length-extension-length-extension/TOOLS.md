# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`hash-attacks-and-length-extension-length-extension`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `hashpump` | `hashpump -s <sig> -d <data> -a <append> -k <len>` | Produces the extended message and digest for a given secret length | build from source, POSIX |
| `python` | `python -c "import hmac,hashlib;print(hmac.new(b'k'*24,b'user=alice','sha256').hexdigest())"` | The non-extendable value for the same inputs, as a control | CPython |
| `xxd` | `xxd -g1 extended.bin` | Shows the `0x80` glue byte and the zero run, which confirms the padding was computed correctly | POSIX |
| `openssl` | `openssl dgst -sha256 -mac HMAC -macopt hexkey:$(python -c "print('11'*24)") msg.bin` | Independent HMAC check without Python | OpenSSL 3.x |

## Minimal script shape

```python
# Offline reproduction harness: proves extendability without a live target.
import hashlib
import struct
import subprocess
import sys

def glue(msg_len: int, block: int = 64) -> bytes:
    pad = b"\x80" + b"\x00" * ((block - (msg_len + 9) % block) % block)
    return pad + struct.pack(">Q", msg_len * 8)

def reproduce(secret_len: int, known: bytes, suffix: bytes) -> tuple[bytes, str]:
    secret = b"k" * secret_len                     # lab secret, not a real one
    digest = hashlib.sha256(secret + known).hexdigest()
    out = subprocess.run(["hashpump", "-s", digest, "-d", known.decode(),
                          "-a", suffix.decode(), "-k", str(secret_len)],
                         capture_output=True, text=True, check=True).stdout
    new_msg, new_sig = out.splitlines()[:2]
    # verify against the same construction, offline
    ok = hashlib.sha256(secret + new_msg.encode("latin-1")).hexdigest() == new_sig
    return new_msg.encode("latin-1"), ("accepted" if ok else "rejected")

if __name__ == "__main__":
    print(reproduce(24, b"user=alice", b"&role=admin"))
```

An `accepted` result proves the construction is extendable; the production verifier then only needs the parser-tolerance check from Class 3.
