# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`firmware-extraction-and-emulation`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `binwalk` | `binwalk -e firmware.bin` | Layer signatures and offsets, with extraction | POSIX |
| `unsquashfs` | `unsquashfs -d rootfs fs.squashfs` | Readable extraction of a SquashFS rootfs | squashfs-tools |
| `ubireader` | `ubireader_extract_images firmware.bin` | UBI and UBIFS extraction, which `binwalk` handles unevenly | Python |
| `qemu-system-arm` | `qemu-system-arm -M versatilepb -kernel zImage -nographic` | Runtime observation of init scripts | QEMU |
| `cramfsck` | `cramfsck -x rootfs fs.cramfs` | CramFS extraction | cramfs-tools |
| `firmadyne` | `sudo ./fat.py firmware.bin` | Automated network harness for an emulated image | POSIX |

## Minimal script shape

```python
# Inventory the extraction: layer offsets, filesystem type, and high-signal paths.
import pathlib
import re
import subprocess

SIGNATURES = re.compile(r"^(\d+)\s+0x[0-9A-F]+\s+(.+)$", re.M)
HIGH_SIGNAL = ("etc/shadow", "etc/passwd", "etc/ssl/private", "etc/init.d", "usr/bin/telnetd")

def layers(bin_path: str) -> list[dict]:
    out = subprocess.run(["binwalk", bin_path], capture_output=True, text=True).stdout
    return [{"offset": int(m.group(1)), "desc": m.group(2).strip()}
            for m in SIGNATURES.finditer(out)]

def high_signal(root: str) -> list[str]:
    hits = []
    for p in pathlib.Path(root).rglob("*"):
        rel = str(p).replace("\\", "/")
        if any(s in rel for s in HIGH_SIGNAL) and p.is_file():
            hits.append(rel)
    return hits

if __name__ == "__main__":
    print({"layers": layers("firmware.bin"), "high_signal": high_signal("rootfs")[:20]})
```

The `layers` list is the evidence chain for the extraction; each `high_signal` path is where a content finding would live and is the locator the report cites.
