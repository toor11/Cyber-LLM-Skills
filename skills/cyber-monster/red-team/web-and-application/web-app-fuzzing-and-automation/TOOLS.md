# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`web-app-fuzzing-and-automation`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `ffuf` | `ffuf -w list.txt:FUZZ -u 'https://target.example/api/coupon/FUZZ' -mc all -ac -rate 20 -o out.json` | Drive the position with a wordlist, auto-calibrate out catch-alls, and cap the rate to a safe envelope | Linux, Windows, macOS |
| `nuclei` | `nuclei -u https://target.example -t custom-template.yaml -rl 10` | Replay a confirmed, endpoint-specific signature at a limited rate for regression and scope-wide checks | Cross-platform |
| `Burp Suite Intruder` | `Sniper attack on one marked position, grep-match the oracle string, with throttle set in the Resource Pool` | Run a calibrated single-position sweep while reading the declared oracle column | Cross-platform |
| `curl` | `curl -sS -o /dev/null -w '%{http_code} %{size_download} %{time_total}\n' 'https://target.example/api/coupon/FUZZBASE01'` | Hand-capture the baseline triple used to triage every automated candidate | Cross-platform |

## Minimal Script Shape

A calibration harness: it learns a noise band from benign controls, then flags a candidate only when it falls outside that band, mirroring how a tool's auto-calibration should behave.

```python
import urllib.request
import urllib.error

BASE = 'https://target.example/api/coupon/'

def probe(value):
    req = urllib.request.Request(BASE + value,
                                 headers={'User-Agent': 'authorised-assessment'})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, len(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, len(exc.read())

controls = [probe('FUZZBASE01'), probe('FUZZBASE02'), probe('FUZZBASE03')]
sizes = [c[1] for c in controls]
band = max(sizes) - min(sizes)
candidate = probe('AAAAAAAA')
delta = min(abs(candidate[1] - s) for s in sizes)
print({'controls': controls, 'noise_band': band,
       'candidate': candidate, 'is_differential': delta > max(band, 16)})
```
