# Verification Probes and Expected Differentials

> Sub-skill: [`crypto-implementation-review`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Boundary-ambiguity probes

```text
# Two logical messages, one serialisation: does the verifier accept both?
python - <<'CRYPTOIMPLEMENTA_CLASS1'
from app.tokens import issue, check
a = issue("alice|role=admin", "user")     # delimiter inside a field
b = issue("alice", "role=admin")
print("a == b ?", a == b)
for t in (a, b):
    print(t[:48], "->", check(t))
CRYPTOIMPLEMENTA_CLASS1
```

Expected differential: a length-prefixed or JSON-encoded frame produces two different tokens and two different parses; a delimiter-joined frame produces tokens that parse into the wrong field split.

```text
# Duplicate-key probe against a signed JSON payload.
python - <<'CRYPTOIMPLEMENTA_CLASS1'
import json  # class 1 boundaryambiguity probes
payload = '{"role":"user","role":"admin"}'
print("python:", json.loads(payload))     # last key wins
CRYPTOIMPLEMENTA_CLASS1
```

Expected differential: the verifier and the consumer reading the same signed blob differently is the finding; identical parses mean the composition is consistent.

## Class 2 — MAC-construction probes

```text
# Offline: confirm the MAC is a concatenation rather than HMAC by structure.
rg -n --no-heading "(sha1|sha256|md5)\(\s*(key|secret)\s*\+" -g '!test*'
rg -n --no-heading "hmac\.new|HMAC\(|createHmac" -g '!test*'
```

Expected differential: the first pattern matching while the second does not is a length-extension candidate; both matching in different files means you must trace which path is live.

## Class 3 — Parameter-vs-threat probes

```text
# Extract the declared parameters so the report can compare them to a stated level.
python - <<'CRYPTOIMPLEMENTA_CLASS3'
import re, pathlib
for p in pathlib.Path(".").rglob("*.py"):
    t = p.read_text(errors="ignore")
    for m in re.finditer(r"pbkdf2_hmac\([^)]*\)|scrypt\([^)]*\)|argon2\w*\([^)]*\)", t):
        print(p, m.group(0)[:90])
CRYPTOIMPLEMENTA_CLASS3
```

Expected differential: no traffic — the output is the parameter inventory you cite against the deployment's data lifetime and the attacker's assumed budget.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
