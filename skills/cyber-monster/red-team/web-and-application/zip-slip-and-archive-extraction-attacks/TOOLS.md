# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`zip-slip-and-archive-extraction-attacks`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `unzip` | `unzip -l suspect.zip` | List archive entry names without extracting, so parent-relative, absolute, and link entries are visible before any write happens | Linux, macOS, Windows |
| `bsdtar (libarchive)` | `bsdtar -tvf suspect.tar` | Show member typeflags and symlink/hardlink targets that a flat ZIP listing does not expose, which identifies the symlink-escape mode | Cross-platform |
| `7z` | `7z l -slt suspect.7z` | Print per-entry technical detail including link attributes and absolute names relevant to the name-escape and symlink modes | Linux, Windows, macOS |
| `Semgrep` | `semgrep --config auto .` | Static source-to-sink pass that flags `tarfile.extractall` and join-without-containment sinks before any runtime test | Cross-platform |

## Minimal Script Shape

A non-destructive containment checker: given an extraction root and candidate entry names, it resolves each name against the root and reports which would escape, without unpacking anything.

```python
import os
import sys


def escapes_root(root, entry_name):
    root = os.path.realpath(root)
    resolved = os.path.realpath(os.path.join(root, entry_name))
    return resolved != root and not resolved.startswith(root + os.sep)


def main(root, names):
    verdicts = [(name, escapes_root(root, name)) for name in names]
    for name, bad in verdicts:
        print("ESCAPES" if bad else "contained", name)
    print("finding" if any(bad for _, bad in verdicts) else "non-finding")


if __name__ == "__main__":
    extraction_root = sys.argv[1] if len(sys.argv) > 1 else "./extract_root"
    entries = sys.argv[2:] or ["ok/file.txt", "../marker.txt", "/tmp/marker.txt"]
    main(extraction_root, entries)
```
