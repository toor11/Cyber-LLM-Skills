# Verification Probes and Expected Differentials

> Sub-skill: [`hash-attacks-and-length-extension-collision-and-bypass`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Comparison-semantics inventory

```text
# Loose comparisons on digest-shaped variables.
rg -n --no-heading "(md5|sha1|hash)\s*\([^)]*\)\s*==|==\s*\$?(stored|expected)_?(digest|hash)" -g '!vendor'
rg -n --no-heading "strcmp\(|substr\([^)]*hash[^)]*,\s*0\s*," -g '!vendor'
```

Expected differential: `hash_equals`, `compare_digest`, or `===` on full width is a control; `==`, `strcmp`, or a `substr` is the bypass candidate.

## Class 2 — Coercion probe (offline)

```text
# Find an input whose digest begins "0e" and continues with digits only, then show
# that the language's loose comparison accepts it against a different digest.
php -r '$i=0; while(true){ $h=md5("t".$i); if(preg_match("/^0e[0-9]+$/",$h)){ echo $i," ",$h,"\n"; break;} $i++; }'
php -r 'var_dump("0e123456" == "0e999999");'   # true on PHP with loose comparison
```

Expected differential: `true` from the second command means the comparison is coercing; `false` (PHP 8 string-to-number changes) means the coercion branch has narrowed and you must check the specific version.

## Class 3 — Truncation width probe

```text
# Compute the collision work for the width you actually found in the comparison.
python - <<'HASHATTACKSAND9EE5_CLASS3'
for hexchars in (4, 8, 12, 16, 32, 64):
    print(f"{hexchars:>3} hex chars -> {hexchars*4:>3} bits, birthday ~2^{hexchars*2}")
HASHATTACKSAND9EE5_CLASS3
```

Expected differential: no traffic — the table is what you cite to justify severity for a truncated comparison.

## Class 4 — Collision substitution

```text
# Verify the verifier accepts a published collision pair; do not generate new ones.
python - <<'HASHATTACKSAND9EE5_CLASS4'
import hashlib  # hash-attacks-and-length-extension-collision-and-bypass: class 4 collision substitution
a, b = open("collide_a.bin","rb").read(), open("collide_b.bin","rb").read()
print("same md5:", hashlib.md5(a).hexdigest() == hashlib.md5(b).hexdigest())
print("same content:", a == b)
HASHATTACKSAND9EE5_CLASS4
```

Expected differential: equal digests with different content proves the digest cannot be the approval boundary; a verifier that also compares size and content hash closes it.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
