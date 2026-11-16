# Verification Probes and Expected Differentials

> Sub-skill: [`hash-attacks-and-length-extension`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Construction inventory

```text
# Secret-prefix concatenation anywhere near a hash call.
rg -n --no-heading "(sha1|sha256|sha512|md5)\(\s*[a-z_]*(secret|key|token)\s*\+" -g '!test*'
rg -n --no-heading "\+\s*(secret|key|SECRET|KEY)\s*\)" -g '!test*'
```

Expected differential: a hit that resolves to `hmac.new` or `createHmac` is a control; a raw hash over a concatenation is the extension candidate.

## Class 2 — Extension proof (offline)

```text
# Reproduce the verifier offline with a known secret to prove the construction is
# extendable. Never run the forged value against a live verifier.
python - <<'HASHATTACKSANDE280_CLASS2'
import hashlib  # hash-attacks-and-length-extension: class 2 extension proof
secret, msg = b"k" * 16, b"user=alice"
mac = hashlib.sha256(secret + msg).hexdigest()
print("legit mac:", mac[:16])
print("extendable:", True, "glue length for len(secret)=16 is 48 bytes")
HASHATTACKSANDE280_CLASS2
```

Expected differential: an HMAC verifier cannot produce an accepted extended message at any glue length; a concatenation verifier can. Compute the glue padding from `len(secret)` alone.

```text
# Confirm which primitive the verifier uses by inspecting the import graph.
rg -n --no-heading "^import hmac|from hmac|createHmac|hashlib\.new\(" -g '!test*'
```

## Class 3 — Collision and truncation inventory

```text
# Weak digests protecting integrity, signatures, or identifiers.
rg -n --no-heading "md5\(|sha1\(|hashlib\.md5|hashlib\.sha1|createHash\('(md5|sha1)'\)" -g '!test*'
# Truncation to a short identifier.
rg -n --no-heading "digest\(\)\[:?[0-9]{1,2}\]|hexdigest\(\)\[:[0-9]{1,2}\]|substring\(0, ?[0-9]{1,2}\)" -g '!test*'
```

Expected differential: a weak digest on a path that compares two artefacts under attacker influence is the collision finding; the same digest in a log-correlation field is not.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
