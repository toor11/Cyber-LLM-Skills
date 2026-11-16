# Verification Probes and Expected Differentials

> Sub-skill: [`prng-and-nonce-attacks-signature-nonce-reuse`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Repeated-nonce detection

```text
# Group published signatures by r; a repeat across distinct messages is the finding.
python - <<'PRNGANDNONCEATBA85_CLASS1'
import collections, json
sigs = [json.loads(l) for l in open("sigs.jsonl")]
by_r = collections.defaultdict(list)
for s in sigs:  # prng-and-nonce-attacks-signature-nonce-reuse: class 1 repeatednonce detection
    by_r[s["r"]].append(s["z"])
for r, zs in by_r.items():
    if len(set(zs)) > 1:
        print("REPEATED NONCE r =", r[:24], "messages:", len(set(zs)))
print("checked", len(sigs), "signatures over", len(by_r), "distinct r values")
PRNGANDNONCEATBA85_CLASS1
```

Expected differential: all-distinct `r` closes the repeated-nonce branch; any group with more than one distinct `z` is the finding, and the group size tells you how many keys are implicated.

## Class 2 — Bias measurement

```text
# Bit-length distribution of r as a proxy for k's distribution across signatures.
python - <<'PRNGANDNONCEATBA85_CLASS2'
import json, statistics  # prng-and-nonce-attacks-signature-nonce-reuse: class 2 bias measurement
rs = [int(json.loads(l)["r"], 16) for l in open("sigs.jsonl")]
bits = [r.bit_length() for r in rs]
print("min:", min(bits), "median:", statistics.median(bits), "max:", max(bits), "n:", len(bits))
PRNGANDNONCEATBA85_CLASS2
```

Expected differential: a tight distribution near the order's bit length suggests unbiased nonces; a cluster at lower bit lengths is the bias the hidden-number lattice consumes, and the spread quantifies the known bits.

## Class 3 — Generator provenance

```text
# Which source supplies k, and is it a CSPRNG or a deterministic derivation?
rg -n --no-heading -B4 -A4 "\bk\s*=|nonce|randrange|randint|urandom" -g '!test*' | rg -i "sign|ecdsa|dsa"
```

Expected differential: `k` derived inside the library or from `os.urandom` at full width is a control; `random`, a truncated source, or an application-supplied `k` is the finding.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
