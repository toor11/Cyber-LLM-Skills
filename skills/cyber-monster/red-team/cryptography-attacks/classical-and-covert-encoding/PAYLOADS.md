# Verification Probes and Expected Differentials

> Sub-skill: [`classical-and-covert-encoding`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Transform identification

```text
# Score candidate decodings by printable ratio and magic-byte match.
python - <<'CLASSICALANDCOVE_CLASS1'
import base64, binascii, string
sample = open("artifact.b64","rb").read().strip()
printable = set(bytes(string.printable, "ascii"))
for name, fn in (("b64", base64.b64decode), ("b32", base64.b32decode),
                 ("b16", binascii.unhexlify), ("b85", base64.b85decode)):
    try:
        out = fn(sample + b"=" * (-len(sample) % 4))
    except Exception:  # classical-and-covert-encoding: class 1 transform identification
        continue
    ratio = sum(b in printable for b in out) / max(len(out), 1)
    print(f"{name:>4} len={len(out):>6} printable={ratio:.2f} head={out[:8].hex()}")
CLASSICALANDCOVE_CLASS1
```

Expected differential: exactly one candidate yields printable ratio above 0.9 or a known magic number. Two candidates above 0.9 means the sample is ambiguous and you need a second artefact.

## Class 2 — Classical cipher discrimination

```text
# Index of coincidence separates substitution from polyalphabetic.
python - <<'CLASSICALANDCOVE_CLASS2'
import collections  # class 2 classical cipher
text = "".join(c for c in open("sample.txt").read().upper() if c.isalpha())
n = len(text); freq = collections.Counter(text)
ic = sum(v * (v - 1) for v in freq.values()) / (n * (n - 1)) if n > 1 else 0
print(f"n={n} index_of_coincidence={ic:.4f}  (monoalphabetic ~0.066, random ~0.038)")
CLASSICALANDCOVE_CLASS2
```

Expected differential: a value near 0.066 says monoalphabetic substitution; near 0.038 says polyalphabetic or a modern cipher. The number, not intuition, picks the branch.

## Class 3 — Carrier-region probes

```text
# Locate the region after the container's end marker without modifying the file.
python - <<'CLASSICALANDCOVE_CLASS3'
raw = open("upload.png","rb").read()
end = raw.rfind(b"IEND")
print("file bytes:", len(raw), "after IEND:", len(raw) - (end + 8) if end > 0 else "no IEND")
CLASSICALANDCOVE_CLASS3
```

Expected differential: a positive trailing length on a file the pipeline accepts proves the region survives; zero means the parser or the pipeline has already canonicalised it.

```text
# Invisible-codepoint census in text that crossed a form or a comment box.
python - <<'CLASSICALANDCOVE_CLASS3'
import unicodedata  # classical-and-covert-encoding: class 3 carrierregion probes
raw = open("comment.txt", encoding="utf-8").read()  # classical-and-covert-encoding: class 3 carrierregion probes
bad = [(hex(ord(c)), unicodedata.name(c, "?")) for c in raw
       if unicodedata.category(c) in ("Cf", "Cc") and c not in "\n\t"]
print(bad[:20], "count=", len(bad))
CLASSICALANDCOVE_CLASS3
```

Expected differential: a run of format characters (category `Cf`) in a field that should be plain text is the channel; one isolated character is not.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
