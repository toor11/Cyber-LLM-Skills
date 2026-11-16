# Verification Probes and Expected Differentials

> Sub-skill: [`block-cipher-modes-and-padding-oracles`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Block-repetition probes (ECB)

```text
# Encrypt a plaintext of 32, 48 and 64 identical bytes through the real path and
# compare block boundaries. ECB shows repeats; CBC does not.
python - <<'BLOCKCIPHERMOD3DE1_CLASS1'
from collections import Counter
from app.crypto import seal            # your own call site, offline
for n in (16, 32, 48, 64):
    ct = seal(b"A" * n, tenant="t1")
    blocks = [ct[i:i+16] for i in range(0, len(ct) - len(ct) % 16, 16)]
    print(n, "distinct_blocks=", len(Counter(blocks)), "of", len(blocks))
BLOCKCIPHERMOD3DE1_CLASS1
```

Expected differential: ECB prints `distinct_blocks` stuck at 2 (or 3) regardless of `n`; CBC prints `n/16` distinct blocks. The floor is the proof, and the exact number also tells you the prefix offset.

## Class 2 — Malleability probes (CBC)

```text
# Flip one bit in the ciphertext block preceding the field you control, then parse.
python - <<'BLOCKCIPHERMOD3DE1_CLASS2'
ct = bytearray(open("sample.bin", "rb").read())
ct[16 + 5] ^= 0x01          # block 1, byte 5 -> flips the same bit in block 2
open("sample.flip.bin", "wb").write(ct)
BLOCKCIPHERMOD3DE1_CLASS2
python - <<'BLOCKCIPHERMOD3DE1_CLASS2'
from app.crypto import open_record
print(open_record(open("sample.flip.bin","rb").read()))
BLOCKCIPHERMOD3DE1_CLASS2
```

Expected differential: an authenticated path rejects with a tag error; a bare CBC path returns a record whose block 1 is noise and whose block 2 differs from the baseline in exactly one bit. Only the second outcome is a finding.

## Class 3 — Oracle-distinguishability probes (padding)

```text
# Two structurally invalid ciphertexts: bad length vs bad padding. Compare the
# response shape, not the response text.
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' -X POST "$API/decrypt" --data-binary @badlen.bin
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' -X POST "$API/decrypt" --data-binary @badpad.bin
```

Expected differential: identical code and identical byte count means no oracle is exposed; a different code, a different body length, or a repeatable timing gap of more than the baseline jitter is the oracle.

## Class 4 — Padding-library behaviour (offline)

```text
python - <<'BLOCKCIPHERMODES_CLASS4'
from cryptography.hazmat.primitives import padding
u = padding.PKCS7(128).unpadder()
try:
    u.update(b"\x00" * 15 + b"\x02")   # syntactically valid, semantically odd
    print("accepted_15_plus_02")
except ValueError as exc:  # block-cipher-modes-and-padding-oracles: class 4 paddinglibrary behaviour
    print("rejected:", type(exc).__name__)
BLOCKCIPHERMODES_CLASS4
```

Expected differential: the library rejects only when the last byte is zero or exceeds the block size, which is why the oracle needs the caller's error mapping rather than the library alone.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
