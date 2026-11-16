# Verification Probes and Expected Differentials

> Sub-skill: [`symmetric-cipher-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Nonce-lifecycle probes

```text
# Where does the nonce come from, and does it survive a restart?
rg -n --no-heading "MODE_CTR|Counter\.new|nonce\s*=|IvParameterSpec|iv\s*=" -g '!test*'
rg -n --no-heading "time\.time\(\)|datetime\.now|sequence|serial|nextval" -g '!test*'
```

Expected differential: a nonce from `os.urandom` or a persisted counter is a control; a counter constructed in-process or derived from a timestamp is the finding.

## Class 2 — Restart-repeat probe

```text
# Encrypt the same plaintext, restart the service, encrypt again, compare prefixes.
python - <<'SYMMETRICCIPHE7903_CLASS2'
from app.crypto import encrypt_row
a = encrypt_row("tenant-a", b"probe-plaintext-0001")
print("first  :", a[:16].hex())
input("restart the service, then press enter")
b = encrypt_row("tenant-a", b"probe-plaintext-0001")
print("second :", b[:16].hex())
print("REPEATED NONCE" if a[:12] == b[:12] else "distinct nonce")
SYMMETRICCIPHE7903_CLASS2
```

Expected differential: distinct prefixes mean the nonce does not reset; identical prefixes prove the counter reinitialises, which is the finding.

## Class 3 — Nonce-width and volume arithmetic

```text
# Collision probability for the observed nonce width at the deployment's volume.
python - <<'SYMMETRICCIPHE7903_CLASS3'
from math import log2  # symmetric-cipher-attacks: class 3 noncewidth and
for bits, messages in ((32, 10**6), (64, 10**9), (96, 10**9)):
    p = messages ** 2 / 2 ** (bits + 1)
    print(f"nonce_bits={bits:>3} messages={messages:>12} collision_p={p:.2e}")
SYMMETRICCIPHE7903_CLASS3
```

Expected differential: no traffic. A probability above `2^-32` is worth a design note; above `2^-20` it is a finding at the stated volume.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
