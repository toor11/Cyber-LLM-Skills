# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`injection-detection-methodology-confirmation-discipline`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `for i in $(seq 1 5); do curl -sS -o /dev/null -w '%{size_download} %{time_total}\n' 'https://target.example/r?q=benign'; done` | Collect repeated benign samples to compute the noise band before judging any probe | Linux, macOS |
| `Burp Suite Repeater` | `Use 'Send group in sequence (separate connections)' to interleave probe, benign, and escaped-probe requests` | Spread caching and load effects across the sequence so the differential is attributable | Cross-platform |
| `Python statistics` | `python3 -c 'import statistics; ...'` | Compute medians and the noise band so the confirm decision is numeric, not impressionistic | Cross-platform |
| `jq` | `jq ".[].time_total" samples.json` | List recorded sample timings so probe and control distributions can be compared | Cross-platform |

## Minimal Script Shape

A confirmation-discipline harness: it takes repeated samples for two benign controls, the probe, and an escaped probe, computes a noise band from the controls, and prints confirmed only when the probe exceeds the band while the escaped probe reverts to baseline.

```python
import statistics

# Each list holds repeated measurements (for example response size or elapsed time)
samples = {
    "control_a": [100, 101, 99, 100],
    "control_b": [102, 100, 101, 103],
    "probe": [240, 238, 242, 239],
    "escaped_probe": [101, 100, 102, 99],
}
THRESHOLD = 20

def med(key):
    return statistics.median(samples[key])

base = statistics.median(samples["control_a"] + samples["control_b"])
noise = abs(med("control_a") - med("control_b"))
exceeds = abs(med("probe") - base) > max(noise * 3, THRESHOLD)
reverts = abs(med("escaped_probe") - base) <= max(noise, 1)
print({"base": base, "noise_band": noise, "exceeds_band": exceeds,
       "reverts": reverts, "confirmed": exceeds and reverts})
```
