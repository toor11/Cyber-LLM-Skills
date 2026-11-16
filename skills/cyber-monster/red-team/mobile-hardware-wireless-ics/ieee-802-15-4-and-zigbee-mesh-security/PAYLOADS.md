# Verification Probes and Expected Differentials

> Sub-skill: [`ieee-802-15-4-and-zigbee-mesh-security`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Key-model inventory

```text
# Firmware strings for default keys and install-code handling.
strings -a firmware.bin | rg -i "zigbeealliance|superSecret|default.*key|install.?code" | head -10
# And the Touchlink symbols, which show whether the path exists.
rg -a -n "zll|touchlink|commission" firmware.bin | head -5
```

Expected differential: `ZigBeeAlliance09` in the image is the finding on its own; a device that reads an install code from a provisioning area is the control.

## Class 2 — Join-path capture

```text
# Passive capture of a join on the channel in use.
wireshark -i mon0 -Y 'wlan.fc.type == 3 || zbee_aps' -w join.pcapng
tshark -r join.pcapng -Y "zbee_aps.cmd.id == 0x05" -T fields -e zbee_aps.cmd.keytype
```

Expected differential: a Transport Key command with key type 0x01 encrypted under a link key that never changes is the finding; an install-code join followed by a Trust Center link-key update (type 0x04) is the control.

## Class 3 — Touchlink proximity probe (lab only)

```text
# With a lab device powered and no network credentials: does it accept a Touchlink join?
zigbee2mqtt-touchlink scan
# Or with a vendor tool: initiate Touchlink commissioning and observe the device's response.
```

Expected differential: a device that accepts a Touchlink join with no Trust Center involvement is the finding; a device that ignores or fails the Touchlink start is the control.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
