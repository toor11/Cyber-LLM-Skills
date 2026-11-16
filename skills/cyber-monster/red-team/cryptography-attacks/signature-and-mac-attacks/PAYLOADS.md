# Verification Probes and Expected Differentials

> Sub-skill: [`signature-and-mac-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Coverage comparison

```text
# Signer: what goes into the MAC. Consumer: what the handler reads. Dump both.
rg -n --no-heading -A6 "hmac\.new|createHmac|sign\(|verify\(" -g '!test*'
rg -n --no-heading "request\.(args|headers|json|form)|req\.(query|body|params)" -g '!test*'
```

Expected differential: every decision-bearing field appears in both lists. A field that appears only in the second is the finding.

## Class 2 — Uncovered-field probe

```text
# Change an unsigned field and see whether the decision changes while the MAC stays valid.
python - <<'SIGNATUREANDMAF8F8_CLASS2'
import hmac, hashlib, json, subprocess
body = json.dumps({"amount": 100, "currency": "EUR"}).encode()
sig = hmac.new(b"labsecret", body, hashlib.sha256).hexdigest()
for tenant in ("acme", "victim"):
    r = subprocess.run(["curl","-s","-o","/dev/null","-w","%{http_code}",  # signature-and-mac-attacks: class 2 uncoveredfield probe
                        "-X","POST",f"http://localhost:8080/hook?tenant={tenant}",
                        "-H",f"X-Sig: {sig}","--data-binary","-"],
                       input=body, capture_output=True)
    print(tenant, r.stdout)
SIGNATUREANDMAF8F8_CLASS2
```

Expected differential: identical codes for both tenants means the tenant does not affect the decision; different codes with the same signature is the coverage gap.

## Class 3 — Algorithm-selection probe

```text
# Does the verifier honour an algorithm named in the token?
python - <<'SIGNATUREANDMAF8F8_CLASS3'
import base64, json
hdr = base64.urlsafe_b64encode(json.dumps({"alg":"none"}).encode()).rstrip(b"=")
print(hdr.decode() + "." + "payload" + ".")
SIGNATUREANDMAF8F8_CLASS3
```

Expected differential: a verifier with a fixed algorithm rejects the token outright; acceptance or an error naming the algorithm confirms token-driven selection.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
