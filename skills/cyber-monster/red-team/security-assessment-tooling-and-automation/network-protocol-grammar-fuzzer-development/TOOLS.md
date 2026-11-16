# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`network-protocol-grammar-fuzzer-development`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** `boofuzz` session/block model with sizers and checksums, or `scapy` for hand-built frames; Python 3.11+.
- **Validation Gate:** `python -m py_compile proto_fuzz.py` then one valid-frame run and one mutated run with the diff recorded.
- Always run against a lab instance you can restart; a fuzz campaign against a shared service is an outage, not an assessment.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `boofuzz` | `python -m boofuzz --help` | Stateful session and block-graph fuzzing against a lab daemon | Cross-platform |
| `scapy` | `python -c "from scapy.all import Raw; print('ok')"` | Hand-built frames when a protocol has no library support | Cross-platform |
| `tcpdump` | `tcpdump -i lo -w capture.pcap 'tcp port 9000'` | Capture the valid exchange the grammar is derived from | Linux, macOS |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json
import socket
import struct
import time

TARGET = ("127.0.0.1", 9000)

def send_frame(payload: bytes) -> None:
    with socket.create_connection(TARGET, timeout=5) as sock:
        sock.sendall(struct.pack(">H", len(payload)) + payload)
        try:
            sock.recv(4096)
        except socket.timeout:
            pass

for i, payload in enumerate([b"GET /\x00", b"GET /" + b"A" * 64 + b"\x00"]):
    try:
        send_frame(payload)
    except OSError as exc:
        print(json.dumps({"case": i, "payload_hex": payload.hex(), "error": str(exc)}))
        time.sleep(1)
```
