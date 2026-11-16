# Verification Probes and Expected Differentials

> Sub-skill: [`hardware-debug-interfaces`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Interface inventory (visual and electrical)

```text
# Continuity and voltage survey, with the device powered from a current-limited supply.
# Identify candidates, then map: GND is continuity to the shield; VCC is a stable rail.
# A UART TX idles high at the IO voltage and shows activity during boot.
python - <<'HARDWAREDEBUGI43C5_CLASS1'
# Expected pad signature for a UART console: three or four pads, one at the rail
# voltage idling high, one toggling at boot, one at ground.
pads = {"pad1": {"v": 0.0, "activity": "none"}, "pad2": {"v": 3.3, "activity": "idle-high"},
        "pad3": {"v": 1.8, "activity": "toggling"}, "pad4": {"v": 0.0, "activity": "none"}}
print({k: v for k, v in pads.items() if v["activity"] != "none"})
HARDWAREDEBUGI43C5_CLASS1
```

Expected differential: a pad that toggles at 115200 baud during boot is a console TX; a pad that idles high is a candidate RX. The finding needs an interactive prompt, not the pad.

## Class 2 — Console interactivity probe

```text
# Attach at the measured baud and send a keystroke at the autoboot prompt.
python -m serial.tools.miniterm /dev/ttyUSB0 115200
# Then, at "Hit any key to stop autoboot", press a key and observe whether a prompt appears.
```

Expected differential: a prompt that accepts `help` or `printenv` is the finding; output that continues to boot regardless of input is a log-only console and therefore the control.

## Class 3 — Guard state

```text
# From a signed diagnostic image or the vendor's tool: the three fuse states.
rg -n --no-heading "secure_boot|flash_encryption|debug_authentication" diag-output.txt
# And whether a flash read returns ciphertext or plaintext.
xxd -l 64 flash.bin
```

Expected differential: `secure_boot_enabled = 1`, `flash_encryption_enabled = 1`, `debug_authentication = locked`, plus ciphertext in the flash read, is the control; any zero or plaintext strings is the finding.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
