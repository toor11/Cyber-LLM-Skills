# Verification Probes and Expected Differentials

> Sub-skill: [`steganography-and-covert-channels`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Appended-region and metadata probes

```text
# Does the container have bytes after its end marker, and what is in metadata?
python - <<'STEGANOGRAPHYADF92_CLASS1'
import pathlib
MARKERS = {b"IEND": "png", b"\xff\xd9": "jpeg", b"%%EOF": "pdf"}
for p in pathlib.Path("uploads").glob("*"):
    raw = p.read_bytes()
    for marker, kind in MARKERS.items():
        i = raw.rfind(marker)
        if i > 0:
            print(kind, p.name, "trailing_bytes:", len(raw) - (i + len(marker)))
STEGANOGRAPHYADF92_CLASS1
exiftool -s -a -G1 -UserComment -ImageDescription -Comment uploads/*.png 2>/dev/null | head -20
```

Expected differential: `trailing_bytes: 0` and empty metadata fields are the control; a positive trailing count or a populated comment field is the finding, with the capacity stated.

## Class 2 — LSB-plane probe

```text
# Compare the frequency of adjacent values in the LSB plane; substitution flattens them.
python - <<'STEGANOGRAPHYADF92_CLASS2'
from PIL import Image as PILImage
import collections  # steganography-and-covert-channels: class 2 lsbplane probe
img = Image.open("uploads/suspect.png").convert("RGB")
lsb = collections.Counter(px & 1 for px in img.getdata().__iter__().__next__() for px in [px]) if False else None
vals = collections.Counter()
for px in img.getdata():
    for c in px:
        vals[c] += 1
pairs = sum(abs(vals[2*i] - vals[2*i+1]) for i in range(128))
print("pair imbalance:", pairs, "(low => LSB substitution likely)")
STEGANOGRAPHYADF92_CLASS2
```

Expected differential: a low pair imbalance relative to a clean reference image of similar content is the anomaly; compare against a control image rather than against an absolute threshold.

## Class 3 — Text codepoint census

```text
# Every format or control codepoint in a text field that should be plain.
python - <<'STEGANOGRAPHYADF92_CLASS3'
import unicodedata  # steganography-and-covert-channels: class 3 text codepoint
raw = open("comment.txt", encoding="utf-8").read()  # steganography-and-covert-channels: class 3 text codepoint
runs = []
for i, c in enumerate(raw):
    if unicodedata.category(c) in ("Cf", "Cc") and c not in "\n\t":
        runs.append((i, hex(ord(c)), unicodedata.name(c, "?")))
print("count:", len(runs), "first:", runs[:10])
STEGANOGRAPHYADF92_CLASS3
```

Expected differential: zero or one isolated codepoint is noise; a run of ten or more in a short field is the channel, and the capacity is the count.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
