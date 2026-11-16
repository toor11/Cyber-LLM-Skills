# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`insecure-deserialization-dotnet-gadgets`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `ysoserial.net` | `ysoserial.exe -g TypeConfuseDelegate -f LosFormatter -c "whoami" --test` | In a lab only, use --test to confirm a chain shape without deploying it against the target | Windows |
| `Burp Suite Repeater` | `Alter one byte of the __VIEWSTATE field and resubmit the postback` | Check whether ViewState MAC rejects a tampered blob, the fastest non-destructive protection test | Cross-platform |
| `viewgen` | `viewgen --check '<__VIEWSTATE>'` | Inspect a ViewState blob's MAC and encryption state without forging a working payload | Linux, macOS, Windows |
| `Semgrep` | `semgrep --config p/csharp --severity ERROR .` | Flag BinaryFormatter, LosFormatter, and TypeFilterLevel.Full usages in source | Cross-platform |

## Minimal Script Shape

A ViewState protection fingerprinter: given the postback fields it reports whether __VIEWSTATE is present, whether a generator field suggests page-specific MAC, and whether a decoded prefix looks encrypted, printing whether forging is even worth attempting.

```python
import base64

def fingerprint(fields):
    vs = fields.get("__VIEWSTATE", "")
    gen = fields.get("__VIEWSTATEGENERATOR")
    present = bool(vs)
    try:
        raw = base64.b64decode(vs)
    except Exception:
        raw = b""
    # LosFormatter plaintext ViewState begins with 0xFF 0x01
    looks_plaintext = raw[:2] == b"\xff\x01"
    return {
        "viewstate_present": present,
        "has_generator": gen is not None,
        "looks_plaintext": looks_plaintext,
        "mac_likely_enforced": present and not looks_plaintext,
    }

sample = {"__VIEWSTATE": "/wEPDwUKLT...", "__VIEWSTATEGENERATOR": "CA0B0334"}
print(fingerprint(sample))
```
