# Verification Probes and Expected Differentials

> Sub-skill: [`hash-attacks-and-length-extension-length-extension`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Construction and reachability

```text
# The verifier must hash a concatenation AND be reachable with attacker input.
rg -n --no-heading -B3 -A6 "sha256\(\s*SECRET\s*\+|sha256\(\s*secret\s*\+" -g '!test*'
```

Expected differential: the hash sits inside a function whose return value gates a parse or an authorisation decision. A signer with no matching verifier is a control.

## Class 2 — Secret-length discovery

```text
# Offline: try candidate secret lengths and see which glue length reproduces the
# verifier's acceptance. Use a local copy of the verifier only.
for k in 8 16 24 32 40 48; do
  echo -n "k=$k "; hashpump -s "$SIG" -d 'user=alice' -a '&role=admin' -k $k 2>/dev/null | head -1 | cut -c1-40
done
```

Expected differential: only the correct `k` yields a digest that the local verifier accepts. Ambiguous matches across several `k` mean the probe needs a longer known message.

## Class 3 — Parser tolerance

```text
# Does the verifier tolerate trailing bytes after a valid MAC?
python - <<'HASHATTACKSAND9E38_CLASS3'
import importlib
v = importlib.import_module("app.tokens").verify
try:
    print("parsed:", v(open("extended.bin","rb").read(), open("extended.mac").read().strip()))
except ValueError as exc:
    print("rejected:", type(exc).__name__, str(exc)[:60])
HASHATTACKSAND9E38_CLASS3
```

Expected differential: a parsed dict containing the appended field is the finding; a length or framing rejection is the control, and the rejection message names the control you should cite.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
