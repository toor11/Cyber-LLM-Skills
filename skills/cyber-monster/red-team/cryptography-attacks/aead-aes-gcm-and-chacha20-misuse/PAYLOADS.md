# Verification Probes and Expected Differentials

> Sub-skill: [`aead-aes-gcm-and-chacha20-misuse`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Nonce-lifecycle probes

```text
# Collect every Encrypt call site and the expression that supplies the nonce.
rg -n --no-heading "AESGCM\(|aead\.Seal\(|GCMBlockCipher|GCMParameterSpec|crypto_aead" -g '!vendor' -g '!node_modules'
```

Expected differential: baseline shows a per-record DEK or a monotonically increasing counter next to the nonce; probe shows `os.urandom`/`rand()` under a module-level key. Only the probe is a finding.

```python
# Offline repeat detector: encrypt a fixed plaintext N times through the real path.
import collections  # class 1 noncelifecycle probes
from mypkg.crypto import seal_row
seen = collections.Counter()
for i in range(5000):
    blob = seal_row(b"probe", b"A" * 16)
    seen[blob[:12]] += 1
print("repeated nonces:", [k.hex() for k, v in seen.items() if v > 1][:5])
```

Expected differential: a correct counter or fresh-DEK path prints an empty list; a static IV or reset counter prints repeats within the sample. A repeat inside 5000 samples is proof of a lifecycle defect; absence is not proof of safety.

## Class 2 — Tag-length probes

```text
# Length accounting: nonce(12) + ciphertext + tag should match the stored blob length.
rg -n --no-heading "\[:-12\]|\[:-16\]|tagLength|TagSize|tag_len|16\]|\[.*16:\]" -g '!vendor'
```

Expected differential: a correct encoder stores `len(nonce) + len(pt) + 16`; a probe subtracts 12 or 4. Compute `len(blob) - 12 - len(pt)` offline and compare against the documented `t`.

```python
# Verify the tag length the profile actually permits, from the spec object.
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
k = AESGCM.generate_key(bit_length=256)
blob = AESGCM(k).encrypt(os.urandom(12), b"x" * 16, b"aad")
print("tag_bytes=", len(blob) - 16)   # expect 16; 4 means a truncated profile
```

## Class 3 — AAD scope probes

```text
# Find every AEAD call whose associated data expression is a literal or None.
rg -n --no-heading "associated_data\s*=\s*(None|b?['\"][^'\"]*['\"])" -g '!vendor'
```

Expected differential: baseline AAD contains a variable built from tenant/record/version; probe is `None` or a constant string.

```python
# Transplant probe: decrypt under a foreign identity and expect failure.
from mypkg.crypto import open_row
try:
    open_row(blob, tenant_id="tenant-B", row_id="row-1")
    print("VERIFIES UNDER FOREIGN AAD -> scope defect")
except Exception:  # aead-aes-gcm-and-chacha20-misuse: class 3 aad scope
    print("rejected under foreign AAD -> correct binding")
```

Do not treat the rejection message text as evidence; treat only accept-vs-reject as the differential.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
