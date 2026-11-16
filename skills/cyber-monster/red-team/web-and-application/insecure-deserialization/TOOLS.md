# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`insecure-deserialization`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Burp Suite Repeater` | `Decode the suspected token, note the format bytes, and resubmit a modified or substituted object` | Confirm the byte source is deserialized by observing behaviour on a substituted object | Cross-platform |
| `Freddy (Burp extension)` | `Enable passive and active scanning for serialization indicators across requests` | Flag Java, .NET, PHP, and Python serialization markers and candidate sinks automatically | Cross-platform |
| `Semgrep` | `semgrep --config p/insecure-deserialization --severity ERROR .` | Find native deserializer calls (ObjectInputStream, pickle.loads, unserialize) with request-derived input | Cross-platform |
| `base64` | `base64 --decode cookie.b64 > cookie.bin` | Write decoded bytes to cookie.bin, then inspect the first 16 with xxd, without executing anything | Linux, macOS |

## Minimal Script Shape

A serialization-surface fingerprinter: it base64-decodes a suspected token and checks its leading bytes against the known signatures for Java, PHP, .NET, and Python pickle, printing which native deserializer the sink most likely uses.

```python
import base64

def fingerprint(token):
    try:
        raw = base64.b64decode(token, validate=False)
    except Exception:
        raw = token.encode(errors="ignore")
    if raw[:2] == b"\xac\xed":
        return "java-serialized (ObjectInputStream)"
    if raw[:4] == b"\x80\x05" or raw[:1] == b"\x80":
        return "python-pickle"
    if raw[:2] in (b"O:", b"a:"):
        return "php-serialize"
    if token.startswith("rO0AB"):
        return "java-serialized (base64 rO0AB)"
    return "no native serialization signature"

for sample in ["rO0ABXNy", "gASVAg==", "Tzo4OiJ"]:
    print({"token": sample, "verdict": fingerprint(sample)})
```
