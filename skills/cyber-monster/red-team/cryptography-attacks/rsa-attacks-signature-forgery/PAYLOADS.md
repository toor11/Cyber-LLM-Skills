# Verification Probes and Expected Differentials

> Sub-skill: [`rsa-attacks-signature-forgery`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Verifier-shape inventory

```text
# Raw modexp and prefix comparisons are the signature of a hand-rolled verifier.
rg -n --no-heading "pow\([^)]*,\s*e\s*,\s*n\)|modPow|modpow|ModExp" -g '!test*'
rg -n --no-heading "startswith\(|copyOf\(|substr\(|\[:len\(expected\)\]" -g '!test*' | rg -i "sig|verify|rec"
```

Expected differential: a library `verify` call is a control; a raw modexp followed by a prefix comparison is the finding.

## Class 2 — Trailing-byte acceptance

```text
# Does the verifier accept a signature with bytes appended or truncated?
python - <<'RSAATTACKSSIGND20D_CLASS2'
import subprocess  # rsa-attacks-signature-forgery: class 2 trailingbyte acceptance
sig = open("sig.bin","rb").read()  # rsa-attacks-signature-forgery: class 2 trailingbyte acceptance
variants = {"orig": sig, "extra": sig + b"\x00", "trunc": sig[:-1]}
for name, blob in variants.items():
    open(f"/tmp/{name}.bin","wb").write(blob)
    r = subprocess.run(["curl","-s","-o","/dev/null","-w","%{http_code}",  # rsa-attacks-signature-forgery: class 2 trailingbyte acceptance
                        "-X","POST","http://localhost:8080/verify","--data-binary",f"@/tmp/{name}.bin"],
                       capture_output=True, text=True)  # rsa-attacks-signature-forgery: class 2 trailingbyte acceptance
    print(name, r.stdout)
RSAATTACKSSIGND20D_CLASS2
```

Expected differential: `orig` accepted and both variants rejected is the control; any variant accepted means the verifier is not length-strict.

## Class 3 — Accepted-region arithmetic

```text
# For e=3, how large is the prefix the verifier actually checks?
python - <<'RSAATTACKSSIGND20D_CLASS3'
n_bits, prefix_bytes = 2048, 8
print("checked bits:", prefix_bytes * 8, "of", n_bits,
      "unconstrained bits:", n_bits - prefix_bytes * 8)
RSAATTACKSSIGND20D_CLASS3
```

Expected differential: this is arithmetic for the report. Any non-zero unconstrained region with `e=3` is constructible; with `e=65537` it is not, which is why the exponent belongs in the finding.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
