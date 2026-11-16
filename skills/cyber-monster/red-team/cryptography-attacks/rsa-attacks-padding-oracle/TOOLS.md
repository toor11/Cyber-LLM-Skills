# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`rsa-attacks-padding-oracle`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `openssl` | `openssl pkeyutl -decrypt -inkey k.pem -pkeyopt rsa_padding_mode:pkcs1 -in c.bin` | Reproduces the v1.5 decryption offline, including the failure mode | OpenSSL 3.x |
| `openssl` | `openssl version -a` | Whether the build includes the implicit-rejection fixes | OpenSSL 3.x |
| `hyperfine` | `hyperfine --warmup 50 --runs 2000 'curl -s -o /dev/null -X POST .../unwrap --data-binary @badpad.bin'` | Timing distribution against the noise floor | any |
| `python` | `python -c "from cryptography.hazmat.primitives.asymmetric import padding; print(padding.PKCS1v15())"` | Confirms the padding object in use in the application | CPython 3.8+ |
| `tcpdump` | `tcpdump -i lo -w h.pcap port 8080` | Captures the response shapes when a client library hides them | POSIX |

## Minimal script shape

```python
# Classify a decrypt route into categorical / timing / no-channel.
import random
import statistics
import time
import urllib.error
import urllib.request

def observe(url: str, body: bytes):
    req = urllib.request.Request(url, data=body, method="POST")
    t0 = time.perf_counter_ns()
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, len(r.read()), time.perf_counter_ns() - t0
    except urllib.error.HTTPError as e:
        return e.code, len(e.read()), time.perf_counter_ns() - t0

def classify(url: str, valid: bytes, invalid: bytes, reps: int = 300) -> dict:
    out = {"valid": [], "invalid": []}
    order = [("valid", valid), ("invalid", invalid)] * reps
    random.shuffle(order)
    for name, body in order:
        out[name].append(observe(url, body))
    shapes = {k: {(s, n) for s, n, _ in v} for k, v in out.items()}
    med = {k: statistics.median(t for _, _, t in v) for k, v in out.items()}
    return {"categorical": shapes["valid"] != shapes["invalid"],
            "timing_ratio": round(med["invalid"] / med["valid"], 3),
            "samples": reps * 2}

if __name__ == "__main__":
    print(classify("http://localhost:8080/unwrap", open("good.bin","rb").read(),
                   open("badpad.bin","rb").read()))
```

A `categorical: True` result is the strong finding; a `timing_ratio` within noise of 1.0 is the negative result you report with the sample size.
