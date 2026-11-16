# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`rf-and-sdr-attacks`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `rtl_433` | `rtl_433 -f 433.92M -A -w cap.cu8` | Capture and decode of common sub-GHz remotes, receive only | rtl-sdr |
| `gqrx`/`GNU Radio` | receive-only flowgraph with a file sink | Modulation characterisation and demodulation | SDR |
| `inspectrum` | `inspectrum cap.cu8` | Visual symbol and pulse analysis | POSIX |
| `URH` | Universal Radio Hacker GUI | Protocol reverse engineering and field comparison, receive first | Python |
| `hackrf_transfer` | `hackrf_transfer -r cap.iq -f 433920000 -s 2000000` | Raw IQ capture | HackRF |

## Minimal script shape

```python
# Classify a sub-GHz remote: fixed code or rolling, and whether a MAC is present.
import collections

def classify(recording: str) -> dict:
    raw = open(recording, "rb").read()
    values = collections.Counter(raw)
    entropy_high = len(values) > 32
    repeated = any(v > len(raw) * 0.3 for v in values.values())
    return {"bytes": len(raw), "distinct": len(values),
            "looks_ook_or_fsk": repeated and not entropy_high,
            "likely_crypto": entropy_high}

if __name__ == "__main__":
    print(classify("/tmp/cap1.cu8"))
```

A `looks_ook_or_fsk` result with a payload that repeats across presses is the fixed-code finding; `likely_crypto` moves the review to key management and the modulation question closes.
