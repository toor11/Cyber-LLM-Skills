# Verification Probes and Expected Differentials

> Sub-skill: [`hardware-debug-interfaces-uart-and-serial`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Baud and pad discovery

```text
# Baud from the shortest pulse in a run of 0x55 bytes, then a capture at that rate.
python - <<'HARDWAREDEBUGI5ED9_CLASS1'
# 0x55 at 115200 baud gives a 8.68 us bit time; measure the narrowest high pulse.
measured_us = 8.68
for baud in (9600, 19200, 38400, 57600, 115200, 230400):
    print(baud, "bit_us=%.2f" % (1_000_000 / baud), "match" if abs(1_000_000/baud - measured_us) < 0.5 else "")
HARDWAREDEBUGI5ED9_CLASS1
python -m serial.tools.miniterm --rts 0 --dtr 0 /dev/ttyUSB0 115200
```

Expected differential: a capture that decodes to readable ASCII at one candidate rate confirms the baud; garbled output at every rate means the pad is not a console TX or the voltage is wrong.

## Class 2 — Autoboot interrupt

```text
# Send a keystroke during the autoboot delay and observe the prompt.
python - <<'HARDWAREDEBUGI5ED9_CLASS2'
import serial, time
s = serial.Serial("/dev/ttyUSB0", 115200, timeout=0.2)
for _ in range(200):                      # ~40 s of boot log
    data = s.read(4096)
    if data:
        print(data.decode(errors="replace"), end="")
    if b"stop autoboot" in data or b"Hit any key" in data:
        s.write(b" ")                     # a single space at the prompt
HARDWAREDEBUGI5ED9_CLASS2
```

Expected differential: a `=>` or `#` prompt after the keystroke is the finding; the boot continuing to the kernel is the control, and the `Loading ... verified` line names the guard.

## Class 3 — Boot-log secret scan

```text
python - <<'HARDWAREDEBUGI5ED9_CLASS3'
import re as regex
log = open("boot.log", errors="ignore").read()
pats = r"(passw(or)?d\s*=\s*\S+|api[_-]?key\s*=\s*\S+|wpa_passphrase=\S+|BEGIN [A-Z ]*PRIVATE KEY)"
for m in re.finditer(pats, log, re.I):
    print("LEAK:", m.group(0)[:60])
HARDWAREDEBUGI5ED9_CLASS3
```

Expected differential: any match is a finding on its own, independent of whether the console accepts input.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
