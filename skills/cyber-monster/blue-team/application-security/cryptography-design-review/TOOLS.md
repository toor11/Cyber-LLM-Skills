# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`cryptography-design-review`](SKILL.md) | Family: **Application Security**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `openssl` | `openssl enc -aes-256-gcm -K $HEXKEY -iv $HEXNONCE -in pt -out ct` | Reproduce a suspected construction against known inputs | Cross-platform |
| `cryptography` (Python) | `Cipher(algorithms.AESGCM(key), modes.GCM(nonce))` | Implement and test the AEAD path in the project's own language | Cross-platform |
| `hashcat` | `hashcat -m 16500 hashes.txt wordlist.txt` (JWT HS256) | Prove a fast-hash key is guessable offline without attacking the service | Cross-platform |
| `semgrep` | `semgrep scan --config p/crypto --error .` | Find mode and key-handling patterns across the codebase | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
from os import urandom
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = AESGCM.generate_key(bit_length=256)
aes = AESGCM(key)
nonce = urandom(12)
aad = b"invoice:4711:tenant-a"

ct = aes.encrypt(nonce, b"amount=4999", aad)
print("roundtrip:", aes.decrypt(nonce, ct, aad))

bad = bytearray(ct); bad[0] ^= 0x01
try:
    aes.decrypt(nonce, bytes(bad), aad)      # must raise InvalidTag
    print("FAIL: tampered ciphertext accepted")
except Exception as exc:
    print("tamper rejected:", type(exc).__name__)
try:
    aes.decrypt(nonce, ct, b"invoice:4712:tenant-a")
    print("FAIL: ciphertext accepted under a different record id")
except Exception as exc:
    print("swap rejected:", type(exc).__name__)
```

## Verification

- The roundtrip prints the plaintext, proving the construction itself works before the negative cases are judged.
- Both negative cases raise; a printed FAIL line is the finding you report.
- The same probe run against the current production scheme shows whether it already authenticates, which decides whether this is a new finding or a migration.
