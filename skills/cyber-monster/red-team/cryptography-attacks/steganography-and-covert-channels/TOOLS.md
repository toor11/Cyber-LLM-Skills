# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`steganography-and-covert-channels`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `binwalk` | `binwalk uploads/suspect.png` | Embedded signatures and appended regions in one pass | POSIX |
| `exiftool` | `exiftool -a -G1 -s uploads/suspect.jpg` | Every metadata field, including vendor comments | any |
| `zsteg` | `zsteg -a uploads/suspect.png` | LSB and bit-plane payloads in PNG and BMP, with the channel named | Ruby gem |
| `steghide` | `steghide info cover.jpg` | Whether a known tool's payload is present, as one signal among several | POSIX |
| `pngcheck` | `pngcheck -v uploads/suspect.png` | Structural validity and trailing data after `IEND` | POSIX |
| `python` | `python -c "import unicodedata;print(unicodedata.category('\u200b'))"` | Confirms a codepoint's category before you build a rule | CPython |

## Minimal script shape

```python
# Capacity report per carrier layer, without extracting anything.
import pathlib
import unicodedata

def appended(raw: bytes, markers: dict[bytes, str]) -> list[tuple[str, int]]:
    out = []
    for marker, kind in markers.items():
        i = raw.rfind(marker)
        if i > 0 and (trailing := len(raw) - (i + len(marker))) > 0:
            out.append((kind, trailing))
    return out

def codepoints(text: str) -> int:
    return sum(1 for c in text if unicodedata.category(c) in ("Cf", "Cc") and c not in "\n\t")

MARKERS = {b"IEND": "png", b"\xff\xd9": "jpeg", b"%%EOF": "pdf"}

if __name__ == "__main__":
    for p in pathlib.Path("uploads").glob("*"):
        found = appended(p.read_bytes(), MARKERS)
        if found:
            print(p.name, found)
```

A positive capacity in any layer is the finding; a zero-capacity report across all layers is the negative result, and the report should name the layers examined.
