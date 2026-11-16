# Verification Probes and Expected Differentials

> Sub-skill: [`prng-and-nonce-attacks-predictable-token-generation`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Space and format probes

```text
# Report the token space from the observed format, without requesting many tokens.
python - <<'PRNGANDNONCEAT1161_CLASS1'
import math, collections  # prng-and-nonce-attacks-predictable-token-generation: class 1 space and
toks = [l.strip() for l in open("samples.txt") if l.strip()]
alpha = len(set("".join(toks)))
L = collections.Counter(len(t) for t in toks).most_common(1)[0][0]
print(f"alphabet={alpha} length={L} space=2^{math.log2(alpha**L):.1f}")
PRNGANDNONCEAT1161_CLASS1
```

Expected differential: a space below `2^40` with no rate limit is the finding; a space above `2^128` closes the enumeration branch regardless of anything else.

## Class 2 — Binding and replay probes

```text
# Does the token work for another subject, and does it work twice?
curl -s -o /dev/null -w 'first use: %{http_code}\n' -X POST "$API/reset/redeem" -d "user=victim&token=$TOKEN"
curl -s -o /dev/null -w 'second use: %{http_code}\n' -X POST "$API/reset/redeem" -d "user=victim&token=$TOKEN"
```

Expected differential: a single-use bound token prints `first use: 200` and `second use: 4xx`. A second `200` is the replay finding; a first `200` against a different subject is the binding finding.

```text
# Attempt budget: how many failures before the token is invalidated?
for i in $(seq 1 12); do
  curl -s -o /dev/null -w "$i:%{http_code} " -X POST "$API/reset/redeem" -d "user=victim&token=00000$i"
done; echo
```

## Class 3 — Exposure probes

```text
# Where does the token travel? Look for query-string carriage and Referer leakage.
rg -n --no-heading "token=|code=|reset\?.*=" -g '!test*'
```

Expected differential: a token in a query string reaches proxy logs and `Referer` headers; a token in a POST body or a fragment does not. The finding cites the specific carriage.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
