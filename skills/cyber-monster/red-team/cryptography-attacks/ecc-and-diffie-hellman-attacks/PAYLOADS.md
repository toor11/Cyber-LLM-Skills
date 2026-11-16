# Verification Probes and Expected Differentials

> Sub-skill: [`ecc-and-diffie-hellman-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Point-validation probes

```text
# Feed a point from a small-order twist and observe whether the peer rejects it.
# Offline: build the point with the library, never against a live peer.
python - <<'ECCANDDIFFIEHELL_CLASS1'
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

CURVE = ec.SECP256R1()
# A point that is not on the curve: the library must refuse to serialize it.
try:
    bad = ec.EllipticCurvePublicNumbers(1, 1, CURVE).public_key()
    print("accepted off-curve point:", bad.public_numbers())
except ValueError as exc:  # ecc-and-diffie-hellman-attacks: class 1 pointvalidation probes
    print("rejected:", exc)
ECCANDDIFFIEHELL_CLASS1
```

Expected differential: a validating path raises `ValueError` at construction; a hand-rolled path accepts the numbers and only fails later, or not at all.

```text
# Confirm the application's own decoder performs validation.
rg -n --no-heading "EllipticCurvePublicNumbers|from_encoded_point|EC_POINT_oct2point|EC_KEY_set_public_key" -g '!test*'
```

## Class 2 — Subgroup and low-order probes

```text
# Does the derived secret repeat across different private scalars for one peer point?
python - <<'ECCANDDIFFIEHELL_CLASS2'
from cryptography.hazmat.primitives.asymmetric import ec
CURVE = ec.SECP256R1()
peer = ec.generate_private_key(CURVE).public_key()
secrets = set()
for _ in range(5):
    priv = ec.generate_private_key(CURVE)
    secrets.add(priv.exchange(ec.ECDH(), peer))
print("distinct shared secrets:", len(secrets), "(expect 5 for a valid point)")
ECCANDDIFFIEHELL_CLASS2
```

Expected differential: five distinct secrets for a valid point; fewer than five means the point confines the output, which is the invalid-curve signature.

## Class 3 — Signature-nonce sanity

```text
# Equal r across different messages indicates a repeated nonce.
python - <<'ECCANDDIFFIEHELL_CLASS3'
import json  # class 3 signaturenonce sanity
sigs = [json.loads(l) for l in open("signatures.jsonl")]
seen = {}
for s in sigs:  # ecc-and-diffie-hellman-attacks: class 3 signaturenonce sanity
    if s["r"] in seen and seen[s["r"]] != s["msg"]:
        print("NONCE REUSE:", seen[s["r"]][:40], "<->", s["msg"][:40])
    seen[s["r"]] = s["msg"]
print("checked", len(sigs))
ECCANDDIFFIEHELL_CLASS3
```

Expected differential: no output for a deterministic or CSPRNG-backed signer; one pair is enough to escalate to [`prng-and-nonce-attacks-signature-nonce-reuse`](../prng-and-nonce-attacks-signature-nonce-reuse/SKILL.md).

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
