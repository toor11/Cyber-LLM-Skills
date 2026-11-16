# Verification Probes and Expected Differentials

> Sub-skill: [`side-channel-and-fault-injection`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Secret-operation inventory

```text
# Where is a secret-dependent decision a single branch?
rg -n --no-heading -B3 -A6 "memcmp|strcmp|==.*stored|check_pin|verify_" firmware-src/
# And where do keys live versus where they are used?
rg -n --no-heading "aes_key|se_key|key\[" firmware-src/ | head -10
```

Expected differential: a comparison inside an authentication function is the fault-skippable candidate; a key that only appears as a handle to a secure element is the control.

## Class 2 — Trace capture and separation (lab, authorised hardware)

```text
# Record power traces of a fixed operation with randomised inputs, then average.
# Tooling: a ChipWhisperer or an oscilloscope with a shunt; capture only, no faults.
python - <<'SIDECHANNELAND6C1A_CLASS2'
# Shape of the analysis: group traces by a secret-dependent intermediate value and
# compare the group means. A separation above the noise floor is the exposure.
import statistics
traces_a, traces_b = [], []
print("groups:", len(traces_a), len(traces_b))
SIDECHANNELAND6C1A_CLASS2
```

Expected differential: no separation after averaging many traces indicates masking or a hardware path; a clear separation at a specific sample index is the exposure, and the index maps to the operation's timing.

## Class 3 — Counter protection

```text
# Is the attempt counter in RAM or in protected storage?
rg -n --no-heading "attempts|retry_count|lockout" firmware-src/
```

Expected differential: a plain variable in RAM is the finding because a power cycle or a fault restores it; a store in protected or monotonic storage is the control.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
