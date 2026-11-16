# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`secure-boot-and-trusted-execution`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `rg` | `rg -n -e 'verify_signature' -e 'load_image' bootloader-src/` | The chain's verification call sites | any |
| `objdump` | `objdump -d bootloader.elf` | Whether the verification call is actually reached on each path | binutils |
| `futility` | `futility verify firmware.bin` | ChromeOS-style verified boot image verification | ChromiumOS |
| `openssl` | `openssl dgst -sha256 -verify pub.pem -signature sig.bin stage.bin` | Manual verification of a stage signature | OpenSSL 3.x |
| `flashrom` | `flashrom -p ch341a_spi -r dump.bin` | The flash content for offline inspection | POSIX |

## Minimal script shape

```python
# Report load paths with no verification over the same region.
import pathlib
import re

LOAD = re.compile(r"load_image\(\s*(\w+)")
VERIFY = re.compile(r"verify_signature\(\s*(\w+)")

def unverified(root: str) -> list[dict]:
    out = []
    for p in pathlib.Path(root).rglob("*.c"):
        text = p.read_text(errors="ignore")
        verified = set(VERIFY.findall(text))
        for m in LOAD.finditer(text):
            region = m.group(1).split(",")[0].strip()
            if region not in verified:
                line = text[:m.start()].count("\n") + 1
                out.append({"file": str(p), "line": line, "region": region})
    return out

if __name__ == "__main__":
    for row in unverified("bootloader-src"):
        print("UNVERIFIED LOAD", row)
```

Each printed row is a chain link with no verification over the region it loads; the file and line are the citation, and the fix is a verification call before the load.
