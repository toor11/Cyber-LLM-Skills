# Verification Probes and Expected Differentials

> Sub-skill: [`password-hashing-and-kdf-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Stored-format inventory

```text
# Group the stored formats in a dump you are authorised to read; never print hashes.
python - <<'PASSWORDHASHINACA8_CLASS1'
import collections, re
rows = (l.strip() for l in open("hashes.txt"))
fam = collections.Counter()
for h in rows:
    if h.startswith("$argon2"): fam["argon2"] += 1
    elif h.startswith("$2"): fam["bcrypt"] += 1
    elif h.startswith("$scrypt"): fam["scrypt"] += 1
    elif re.fullmatch(r"[0-9a-f]{32}", h): fam["md5_hex"] += 1
    elif re.fullmatch(r"[0-9a-f]{64}", h): fam["sha256_hex"] += 1
    else: fam["other"] += 1
print(fam)
PASSWORDHASHINACA8_CLASS1
```

Expected differential: a single family at current parameters is a control; a long tail of `md5_hex` or `sha256_hex` is the finding, with the count as the exposure size.

```text
# Extract bcrypt cost and Argon2 parameters from the encoded hashes.
python - <<'PASSWORDHASHINACA8_CLASS1'
import collections, re
costs = collections.Counter()
for h in open("hashes.txt"):
    m = re.match(r"\$2[aby]\$(\d\d)\$", h.strip())
    if m: costs[int(m.group(1))] += 1
print("bcrypt costs:", dict(sorted(costs.items())))
PASSWORDHASHINACA8_CLASS1
```

Expected differential: all rows at or above the current floor is a control; any row below it is the population that needs rehashing.

## Class 2 — Work-factor measurement

```text
# Measure the defender's cost per verification, which is the reciprocal of the
# attacker's per-guess advantage.
python - <<'PASSWORDHASHINACA8_CLASS2'
import statistics, time  # password-hashing-and-kdf-attacks: class 2 workfactor measurement
from argon2 import PasswordHasher
PH = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
t = []
for _ in range(20):
    t0 = time.perf_counter(); PH.hash("correct horse battery staple"); t.append(time.perf_counter() - t0)
print("median ms per hash:", round(statistics.median(t) * 1000, 1))
PASSWORDHASHINACA8_CLASS2
```

Expected differential: tens of milliseconds per verification is a defensible floor; single-digit milliseconds means the parameters are too low for a password store.

## Class 3 — Downgrade-path probe

```text
# Which branch does a stored value select, and can a request choose it?
rg -n --no-heading -B2 -A4 "startswith\(|legacy|md5\\$|rehash" -g '!test*'
```

Expected differential: a single verifier with `check_needs_rehash` is the control; a second verifier selected by the stored value or a request field is the downgrade.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
