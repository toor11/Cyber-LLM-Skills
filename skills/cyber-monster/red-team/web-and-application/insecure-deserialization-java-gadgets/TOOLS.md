# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`insecure-deserialization-java-gadgets`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `ysoserial` | `java -jar ysoserial.jar URLDNS http://<assessor-controlled-host>/probe` | Generate a DNS-only confirmation object that triggers one lookup during deserialization without running a gadget chain | Linux, Windows, macOS |
| `Freddy (Burp extension)` | `Load Freddy in Burp Extender, then passively scan requests carrying serialized blobs` | Flag active and passive Java, PHP, and Python deserialization sinks in intercepted traffic | Cross-platform |
| `gadgetinspector` | `java -jar gadget-inspector.jar target-app.jar` | Statically enumerate reachable readObject gadget chains on the application classpath | Cross-platform |
| `Semgrep` | `semgrep --config p/java -e 'new ObjectInputStream(...)' .` | Locate ObjectInputStream.readObject sinks that lack a resolveClass allowlist | Cross-platform |

## Minimal Script Shape

A classifier that reports whether a captured parameter value is a Java serialized stream, so the readObject sink can be confirmed before any gadget object is sent.

```python
import base64, sys

JAVA_MAGIC = b"\xac\xed\x00\x05"

def is_java_serialized(blob: bytes) -> bool:
    return blob[:4] == JAVA_MAGIC

def classify(value: str) -> str:
    try:
        raw = base64.b64decode(value, validate=False)
    except Exception:
        return "not-base64"
    return "java-serialized-stream" if is_java_serialized(raw) else "opaque"

for arg in sys.argv[1:]:
    verdict = classify(arg)
    hint = " (sink deserializes; confirm with URLDNS DNS oracle)" if verdict == "java-serialized-stream" else ""
    print(arg[:24], "->", verdict + hint)
```
