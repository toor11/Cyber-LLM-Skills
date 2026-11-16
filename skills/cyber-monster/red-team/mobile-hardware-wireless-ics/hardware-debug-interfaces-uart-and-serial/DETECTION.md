# Detection Signals and Blue-Team Handoff

> Sub-skill: [`hardware-debug-interfaces-uart-and-serial`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Manufacturing test log: a production unit whose boot log contains an interactive prompt, which is the build-configuration check.
- Firmware build audit: a bootloader configuration with `CONFIG_AUTOBOOT_PROMPT` and a non-zero delay in a production target.
- Field telemetry: a device reporting a kernel command line that differs from the signed one.
- Boot log field: a credential-shaped string in the first-stage log, which the device itself can detect and refuse to print.
- Physical security audit: a unit with an accessible UART header, recorded as part of the hardware review.
- Secure boot attestation: a device whose measured boot does not match the expected chain, which is what the interruptible-autoboot path would produce.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
