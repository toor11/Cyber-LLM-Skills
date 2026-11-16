# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`constant-time-and-crypto-side-channel-code-audit`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `rg` | `rg -n -e '==.*mac' -e '!=.*mac' -g '!test*'` | Inventory of candidate comparisons, which is the entry point for the whole audit | any |
| `valgrind` | `valgrind --tool=memcheck --track-origins=yes ./verify` | Uninitialised-secret propagation, a proxy for secret-dependent control flow | Linux, plus the patched ctgrind variant |
| `dudect` | build against `dudect.h` and run `./verify --leak` | Statistical constant-time test with a stated sample size and a t-test threshold | C/C++ targets |
| `hyperfine` | `hyperfine --warmup 100 --runs 1000 './verify --bad-first' './verify --bad-last'` | Distribution comparison at the CLI level when the function has no harness | any |
| `go` | `go doc crypto/subtle.ConstantTimeCompare` | Confirms the exact contract, including the length-equal precondition | Go 1.21+ |

## Minimal script shape

```python
# Two-sample t-style separation test for a candidate comparison. Read-only.
import random
import statistics
import time

def measure(fn, bad_first: bytes, bad_last: bytes, reps: int = 5000) -> dict:
    out = {"first": [], "last": []}
    order = [("first", bad_first), ("last", bad_last)] * reps
    random.shuffle(order)                     # double-blind ordering
    for name, arg in order:
        t0 = time.perf_counter_ns()
        fn(arg)
        out[name].append(time.perf_counter_ns() - t0)
    return {k: (statistics.median(v), statistics.stdev(v)) for k, v in out.items()}

if __name__ == "__main__":
    print(measure(verify, b"1" + b"0" * 31, b"0" * 31 + b"1"))
```

A separation larger than three standard deviations with randomised ordering is evidence; anything smaller is noise and must be reported as such.
