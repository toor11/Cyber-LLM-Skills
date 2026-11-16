# Verification Probes and Expected Differentials

> Sub-skill: [`gnss-and-satellite-link-security`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Receiver capability

```text
# Does the receiver expose OSNMA state? Check the datasheet registers or the API.
rg -n --no-heading -i "osnma|navigation message authentication|galileo" gnss-driver/ | head -10
# And the key material in use:
rg -n --no-heading -i "gsc|public_key|merkle" gnss-driver/ | head -10
```

Expected differential: an OSNMA API plus GSC-sourced keys is the control; no OSNMA references, or an API whose result nothing reads, is the finding.

## Class 2 — Consumer trace

```text
# Who consumes GNSS time and position?
rg -n --no-heading "read_time|gnss_time|position|latitude|longitude" services/ | head -20
rg -n --no-heading -i "not_valid|certificate|expire" services/ | head -10
```

Expected differential: a certificate or log-ordering decision consuming GNSS time is the highest-severity finding; a display-only consumer is the weaker one.

## Class 3 — Shielded spoof-acceptance probe (lab only)

```text
# In a shielded enclosure with a signal generator, shift the reported time and check
# whether the application accepts it. Never radiate outside the enclosure.
python - <<'GNSSANDSATELLI8A28_CLASS3'
from gnss import re as rxad_time_with_osnma, OsnmaError
try:
    t, verified = read_time_with_osnma()
    print("time:", t, "osnma_verified:", verified)
except OsnmaError as exc:
    print("OSNMA rejected the navigation data:", exc)   # the control
GNSSANDSATELLI8A28_CLASS3
```

Expected differential: an `OSNMA rejected` message is the control; a shifted time reported as `osnma_verified: True` would indicate a verification defect, and a shifted time consumed with no verification is the finding.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
