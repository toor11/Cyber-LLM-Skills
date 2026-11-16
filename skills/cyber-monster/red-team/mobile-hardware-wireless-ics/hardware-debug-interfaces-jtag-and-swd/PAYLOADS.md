# Verification Probes and Expected Differentials

> Sub-skill: [`hardware-debug-interfaces-jtag-and-swd`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Transport discovery

```text
# SWD first (two wires), then JTAG; both report a target or an error.
openocd -f interface/cmsis-dap.cfg -f target/stm32f4x.cfg -c "init; dap info; shutdown"
openocd -f interface/ftdi.cfg -f target/stm32f4x.cfg -c "init; scan_chain; shutdown"
```

Expected differential: an IDCODE in the output means the TAP is enabled; `expected 0x2ba01477, got 0x00000000` means no transport, which is the control.

## Class 2 — Guard classification

```text
# After a successful halt: read the debug-authentication state.
openocd -c "init; halt; mdw 0xE0042004 1; resume; shutdown"
# And attempt a bounded flash read; a fully erased result means read-out protection.
openocd -c "init; halt; flash read_bank 0 /tmp/dump.bin 0 4096; shutdown"
xxd -l 64 /tmp/dump.bin
```

Expected differential: `0xFF` across the read region is read-out protection; readable data is the finding; a halt that is refused is authenticated debug.

## Class 3 — Key-location review (offline)

```text
# Is the debug authentication key in the firmware image?
rg -a -n "dbg_key|debug_key|auth_key" firmware.bin | head -5
strings -a firmware.bin | rg -i "jtag|swd|dbg_pass" | head -5
```

Expected differential: a key constant in the image makes the authenticated-debug guard nominal, which is a finding independent of whether the TAP is open.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
