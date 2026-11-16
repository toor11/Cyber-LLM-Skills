# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`python-atheris-and-hypothesis-security-fuzzing`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Hypothesis 6.x with `settings(max_examples=, deadline=)`, Atheris with libFuzzer flags passed after `--`.
- **Validation Gate:** `pytest -q tests/test_props.py --hypothesis-seed=0` with the seed pinned so failures reproduce.
- Hypothesis writes a `.hypothesis/examples` database; committing it makes failures reproducible but leaks generated inputs, so decide deliberately.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `pytest` | `pytest -q tests/test_props.py --hypothesis-seed=0` | Reproducible property run with a fixed seed | Cross-platform |
| `hypothesis` | `python -c "import hypothesis; print(hypothesis.__version__)"` | Pin the version whose shrinking behaviour you rely on | Cross-platform |
| `atheris` | `python -m fuzz_target -runs=0 corpus/` | Replay the corpus without fuzzing | Linux, macOS |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
from hypothesis import given, settings, strategies as st

@given(st.binary(max_size=4096))
@settings(max_examples=500, deadline=2000)
def test_parse_is_total(data):
    try:
        result = parse(data)
    except ValueError:
        return
    assert isinstance(result, dict)
```
