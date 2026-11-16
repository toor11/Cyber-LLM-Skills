# Verification Probes and Expected Differentials

> Sub-skill: [`symmetric-cipher-attacks-weak-key-derivation`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Key-origin inventory

```text
# Where does key material come from? Literals, env vars, KMS, derivations.
rg -n --no-heading "(KEY|SECRET|PASSWORD)\s*=\s*b?[\"'][^\"']{8,}" -g '!test*' -g '!*.example'
rg -n --no-heading "pbkdf2_hmac|scrypt|argon2|generate_data_key|GenerateDataKey" -g '!test*'
```

Expected differential: a literal or a bare hash is the finding; a KMS call or a salted memory-hard derivation is the control.

## Class 2 — Entropy and rate arithmetic

```text
# Guesses per candidate at the measured derivation cost, times the source entropy.
python - <<'SYMMETRICCIPHE2155_CLASS2'
import time, hashlib
t0 = time.perf_counter()
for _ in range(1000):
    hashlib.sha256(b"candidate").digest()
per_sec = 1000 / (time.perf_counter() - t0)
for bits in (20, 30, 40, 50):
    print(f"{bits} bits -> {2**bits / per_sec / 86400:,.0f} GPU-days at {per_sec:,.0f}/s")
SYMMETRICCIPHE2155_CLASS2
```

Expected differential: no traffic. A passphrase space that resolves to hours or days is the finding; a space that resolves to centuries is not, however ugly the derivation looks.

```text
# Same arithmetic for the KDF that is actually in use.
python - <<'SYMMETRICCIPHE2155_CLASS2'
import time
from argon2.low_level import hash_secret_raw, Type
t0 = time.perf_counter()
hash_secret_raw(b"candidate", b"0"*16, time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, type=Type.ID)
print("per-candidate seconds:", round(time.perf_counter() - t0, 3))
SYMMETRICCIPHE2155_CLASS2
```

## Class 3 — Shared-key probe

```text
# Is one key identifier used in more than one service or tenant scope?
rg -n --no-heading "ENCRYPTION_KEY|DATA_KEY|MASTER_KEY" -g '*.yaml' -g '*.env*' -g '!test*'
```

Expected differential: a distinct key per service and tenant is the control; one identifier across many manifests is the blast-radius finding.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
