# Verification Probes and Expected Differentials

> Sub-skill: [`iot-thread-and-openthread-security`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Commissioning-configuration inventory

```text
# Build flags that decide which commissioning paths exist.
rg -n --no-heading "OPENTHREAD_CONFIG_(BLE_TCAT|BORDER_AGENT_EPHEMERAL_KEY|JOINER)" \
  openthread/src/core/config/ build/ 2>/dev/null
# And the PSKd provisioning site.
rg -n --no-heading "otJoinerStart|pskd|PSKd" src/ | head -10
```

Expected differential: a PSKd sourced from provisioning data is the control; a string literal is the fleet-static finding, and the build flags tell you whether TCAT or ePSKc is even available.

## Class 2 — Joiner-window probe

```text
# Record the window duration and whether it closes after a successful join.
ot-ctl commissioner state
ot-ctl joiner port any
sleep 300
ot-ctl commissioner state       # should have expired if the window is bounded
```

Expected differential: a state that expires or a joiner that stops accepting after one success is the control; an accepting joiner long after commissioning is the finding.

## Class 3 — Credential uniqueness

```text
# Across a sample of devices, is the commissioning secret the same?
for d in /dev/ttyACM*; do printf '%s ' "$d"; ot-ctl pskc 2>/dev/null | head -1; done
```

Expected differential: distinct values per device is the control; a repeated value across units is the fleet-static finding, and the manufacturing data is where the fix belongs.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
