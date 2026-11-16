# Verification Probes and Expected Differentials

> Sub-skill: [`symmetric-cipher-attacks-keystream-and-nonce-reuse`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Reuse detection

```text
# Group stored ciphertexts by their nonce prefix; a duplicate group is the finding.
python - <<'SYMMETRICCIPHE14D6_CLASS1'
import collections, pathlib
rows = pathlib.Path("ct").glob("*.bin")
by_nonce = collections.defaultdict(list)
for p in rows:
    blob = p.read_bytes()
    by_nonce[blob[:12]].append(p.name)
dups = {k.hex(): v for k, v in by_nonce.items() if len(v) > 1}
print("duplicate nonce groups:", len(dups))
for k, v in list(dups.items())[:3]: print(" ", k, v[:4])
SYMMETRICCIPHE14D6_CLASS1
```

Expected differential: zero groups means no reuse in the sample; any group is a finding, and the group size tells you how many plaintexts are mutually related.

## Class 2 — XOR structure probe

```text
# XOR two ciphertexts with the same nonce and score the result for structure.
python - <<'SYMMETRICCIPHE14D6_CLASS2'
import string
a = open("ct/a.bin","rb").read(); b = open("ct/b.bin","rb").read()
x = bytes(p ^ q for p, q in zip(a, b))
printable = sum(chr(c) in string.printable for c in x) / max(len(x), 1)
print("printable ratio:", round(printable, 2), "head:", x[:32].hex())
SYMMETRICCIPHE14D6_CLASS2
```

Expected differential: a printable ratio near 1.0 with visible ASCII runs is the reuse proof; a ratio near the random baseline (~0.4 for byte values) means the nonces differ.

## Class 3 — Counter overlap arithmetic

```text
# Probability that two messages with random 64-bit counter starts overlap in a block.
python - <<'SYMMETRICCIPHE14D6_CLASS3'
blocks_per_msg, starts = 4 * 1024 * 4, 10 ** 7        # 64 KiB messages, 10M messages
print("expected overlapping pairs:", starts ** 2 * blocks_per_msg / 2 ** 64)
SYMMETRICCIPHE14D6_CLASS3
```

Expected differential: no traffic. A non-trivial expected overlap count at the deployment's volume is the argument; zero at realistic volume closes the branch.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
