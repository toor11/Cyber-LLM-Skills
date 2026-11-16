# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`file-upload-and-webshell-polyglot-and-archive`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `zipinfo` | `zipinfo -l sample.zip` | List archive member names and attributes to spot traversal, absolute paths, or symlinks before extraction | Linux, macOS |
| `7z` | `7z l -slt sample.zip` | Inspect member metadata including symlink flags without extracting | Linux, macOS, Windows |
| `exiftool` | `exiftool sample.png` | Confirm a polyglot's first-format view stays a valid benign image | Cross-platform |
| `curl` | `curl -sS -F 'file=@sample.zip' https://target.example/import` | Submit the archive to the server-side extraction feature | Cross-platform |

## Minimal Script Shape

An archive-member auditor: it inspects a local zip for symlink, absolute-path, and traversal members and reports whether extraction could reconstitute a file outside the root.

```python
import sys, os, zipfile

def audit(path):
    findings = []
    with zipfile.ZipFile(path) as zf:
        for m in zf.infolist():
            name = m.filename
            is_symlink = (m.external_attr >> 28) == 0xA
            absolute = name.startswith("/") or (len(name) > 1 and name[1] == ":")
            traversal = ".." in name.replace("\\", "/").split("/")
            if is_symlink or absolute or traversal:
                findings.append({"member": name, "symlink": is_symlink,
                                 "absolute": absolute, "traversal": traversal})
    return findings

for arc in sys.argv[1:]:
    bad = audit(arc)
    print({"archive": arc, "unsafe_members": bad, "reconstitution_risk": bool(bad)})
```
