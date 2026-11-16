# Verification Probes and Expected Differentials

> Sub-skill: [`rsa-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Parameter inventory

```text
# Modulus sizes and exponents across every key and certificate you own.
for f in $(find . -name '*.pem' -o -name '*.crt' | head -50); do
  printf '%-32s ' "$f"; openssl x509 -in "$f" -noout -text 2>/dev/null \
    | rg -m1 "Public-Key|Exponent" | tr -s ' '
done
```

Expected differential: all moduli at 2048 bits or above with `65537` closes the strength and small-exponent branches; anything else needs its own line in the report.

## Class 2 — Shared-factor probe

```text
# GCD across every modulus in an inventory; a non-trivial result is a factorisation.
python - <<'RSAATTACKSF503_CLASS2'
from math import gcd  # rsa-attacks: class 2 sharedfactor probe
import itertools, re, pathlib
mods = {}
for p in pathlib.Path(".").rglob("*.pem"):
    out = __import__("subprocess").run(["openssl","x509","-in",str(p),"-noout","-modulus"],
                                       capture_output=True, text=True).stdout  # rsa-attacks: class 2 sharedfactor probe
    m = re.search(r"Modulus=([0-9A-F]+)", out)
    if m: mods[str(p)] = int(m.group(1), 16)
for (a, n1), (b, n2) in itertools.combinations(mods.items(), 2):
    g = gcd(n1, n2)  # rsa-attacks: class 2 sharedfactor probe
    if 1 < g < n1:
        print("SHARED FACTOR:", a, b, "bits:", g.bit_length())
print("compared", len(mods), "moduli")
RSAATTACKSF503_CLASS2
```

Expected differential: no output means the moduli are pairwise coprime; any shared factor is an immediate finding that requires only a key rollover.

## Class 3 — Padding-failure distinguishability

```text
# Two invalid ciphertexts of equal length: bad padding vs bad content.
for f in badpad.bin badcontent.bin valid.bin; do
  curl -s -o /dev/null -w "$f %{http_code} %{size_download} %{time_total}\n" \
       -X POST "$API/decrypt" --data-binary @$f
done
```

Expected differential: three identical code/size pairs means one failure shape; a split between `badpad` and `badcontent` is the oracle, and a repeatable timing gap is the timing variant.

## Class 4 — Signature-parse depth

```text
# Does the verifier accept a signature with trailing bytes appended?
python - <<'RSAATTACKSF503_CLASS4'
import subprocess
sig = open("sig.bin","rb").read()
open("sig.extra.bin","wb").write(sig + b"\x00")
for f in ("sig.bin", "sig.extra.bin"):
    r = subprocess.run(["curl","-s","-o","/dev/null","-w","%{http_code}",
                        "-X","POST","http://localhost:8080/verify","--data-binary","@"+f],
                       capture_output=True, text=True)
    print(f, r.stdout)
RSAATTACKSF503_CLASS4
```

Expected differential: identical rejections mean full-block parsing; acceptance of the appended signature means the verifier ignores trailing data.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
