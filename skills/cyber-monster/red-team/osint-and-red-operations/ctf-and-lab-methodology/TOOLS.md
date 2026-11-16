# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ctf-and-lab-methodology`](SKILL.md) | Family: **OSINT and Red Operations**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** a timestamped notebook plus the standard identification tools; every artefact hashed before analysis.
- **Validation Gate:** one hypothesis recorded with its command, output, and decision before the second attempt.
- Work only in a lab environment you are authorised to use; CTF material is not a licence to test third-party infrastructure.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `file` | `file challenge.bin` | Identify the format before choosing a tool | Cross-platform |
| `sha256sum` | `sha256sum challenge.bin` | Record the artefact hash for reproducibility | Linux, macOS |
| `xxd` | `xxd -l 128 challenge.bin` | First bytes, which often reveal the real format | Linux, macOS |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import hashlib
import time

path = "challenge.bin"
print(time.strftime("%H:%M:%S", time.gmtime()), "sha256",
      hashlib.sha256(open(path, "rb").read()).hexdigest())
with open(path, "rb") as f:
    print("magic", f.read(8).hex())
```
