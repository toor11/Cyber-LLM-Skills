# Verification Probes and Expected Differentials

> Sub-skill: [`constant-time-and-crypto-side-channel-code-audit`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Comparison-shape inventory

```text
# Every equality check on a value that looks like a MAC, token, or hash.
rg -n --no-heading "(==|!=)\s*(hmac|tag|mac|digest|signature|token|expected)" -g '!test*' -g '!vendor'
rg -n --no-heading "bytes\.Equal|strcmp|memcmp|arrayEquals|\.equals\(" -g '!test*'
```

Expected differential: hits that resolve to `compare_digest`, `ConstantTimeCompare`, or `timingSafeEqual` are controls; the rest need operand provenance before they become findings.

## Class 2 — Timing distribution probe

```text
# Compare the operation with inputs differing in the FIRST vs LAST secret byte.
# Repeat 2000 times each; report median and a trimmed mean, not a single run.
python - <<'CONSTANTTIMEANDC_CLASS2'
import statistics, time  # constant-time-and-crypto-side-channel-code-audit: class 2 timing distribution
from app.tokens import verify

def sample(secret: bytes, reps: int = 2000):
    first, last = b"0" * 32, b"0" * 32
    bad_first, bad_last = b"1" + first[1:], last[:-1] + b"1"
    out = {"bad_first": [], "bad_last": []}
    for _ in range(reps):
        for name, tag in (("bad_first", bad_first), ("bad_last", bad_last)):
            t0 = time.perf_counter_ns(); verify(tag, secret); out[name].append(time.perf_counter_ns() - t0)
    return {k: (statistics.median(v), statistics.stdev(v)) for k, v in out.items()}

print(sample(b"s" * 32))
```

Expected differential: a constant-time compare prints medians within the standard deviation of each other; an early-exit compare prints a systematically shorter median for `bad_first`.

## Class 3 — Secret-index inventory

```text
# Table lookups indexed by a variable that also feeds key material.
rg -n --no-heading "\[[a-z_]*(key|secret|nonce)[a-z_]*\[" -g '!test*'
rg -n --no-heading "(/|%)\s*(q|Q|KYBER_Q|prime|modulus)" -g '!test*'
```

Expected differential: an index expression that resolves to public data is a control; one that resolves to key material is a cache-timing candidate whose severity you then bound by table size.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
