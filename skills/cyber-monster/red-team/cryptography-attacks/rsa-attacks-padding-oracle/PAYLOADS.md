# Verification Probes and Expected Differentials

> Sub-skill: [`rsa-attacks-padding-oracle`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Operation classification

```text
# Is RSA used for decryption or for verification on this path?
rg -n --no-heading "PKCS1v15|PKCS1Padding|private_decrypt|RSADecrypt|\.decrypt\(" -g '!test*'
rg -n --no-heading "ECDHE_RSA|TLS_AES.*|Signature.getInstance|verify\(" -g '!test*'
```

Expected differential: a decrypt call with v1.5 padding is in scope; a verify call, or a TLS suite that only signs, is the non-finding.

## Class 2 — Channel enumeration

```text
# Every observable on the decrypt route for two invalid ciphertexts, six samples each.
for f in badpad.bin badcontent.bin; do
  for i in 1 2 3; do
    curl -s -o /dev/null -w "unwrap $f %{http_code} %{size_download} %{time_total}\n" \
         -X POST "$API/unwrap" --data-binary @$f
  done
done
```

Expected differential: identical triples for both files means one failure shape; a consistent split is the categorical oracle, and a consistent timing gap is the timing variant.

## Class 3 — Statistical timing probe

```text
# Randomised, repeated measurement; the shift must exceed the standard deviation.
python - <<'RSAATTACKSPADDC118_CLASS3'
import random, statistics, time, urllib.request, urllib.error
def once(body: bytes) -> float:
    req = urllib.request.Request("http://localhost:8080/unwrap", data=body, method="POST")
    t0 = time.perf_counter_ns()
    try: urllib.request.urlopen(req).read()
    except urllib.error.HTTPError as e: e.read()
    return time.perf_counter_ns() - t0
good, bad = open("badpad.bin","rb").read(), open("badcontent.bin","rb").read()
samples = {"good": [], "bad": []}
order = [("good", good), ("bad", bad)] * 400
random.shuffle(order)
for name, body in order:
    samples[name].append(once(body))
for k, v in samples.items():
    print(k, "median_us=%.1f" % (statistics.median(v)/1000), "stdev_us=%.1f" % (statistics.stdev(v)/1000))
RSAATTACKSPADDC118_CLASS3
```

Expected differential: medians within one standard deviation of each other means no measurable channel at this sample size; a separation larger than three standard deviations is evidence, and the report must state the sample size and the ordering.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
