# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`file-upload-and-webshell-extension-and-mime-bypass`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -F 'file=@shell.phtml.png;type=image/png' https://target.example/upload` | Submit one crafted divergence between declared type and final extension | Cross-platform |
| `file` | `file stored-sample` | Confirm the server-side sniffed type of a stored sample to compare against the validator's decision | Linux, macOS |
| `Burp Suite Intruder` | `Fuzz the filename suffix and Content-Type positions against one benign body` | Enumerate which extension and MIME combination the validator accepts | Cross-platform |

## Minimal Script Shape

A pre-upload divergence checker: it sniffs a local file's magic bytes and compares them to its extension, flagging a crafted file the validator would read as an image while the runtime might execute it.

```python
import sys

MAGIC = {b"\x89PNG": "image/png", b"GIF8": "image/gif", b"\xff\xd8\xff": "image/jpeg"}
EXEC_SUFFIXES = (".php", ".phtml", ".phar", ".asp", ".aspx", ".jsp")

def sniff(path):
    head = open(path, "rb").read(4)
    for sig, mime in MAGIC.items():
        if head.startswith(sig):
            return mime
    return "application/octet-stream"

for path in sys.argv[1:]:
    believed = sniff(path)
    executable = path.lower().endswith(EXEC_SUFFIXES) or path.lower().count(".") > 1
    print({"file": path, "validator_believes": believed,
           "runtime_may_execute": executable,
           "type_disagreement": believed.startswith("image/") and executable})
```
