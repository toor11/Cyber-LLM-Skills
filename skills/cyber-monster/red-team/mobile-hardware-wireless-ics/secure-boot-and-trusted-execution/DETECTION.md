# Detection Signals and Blue-Team Handoff

> Sub-skill: [`secure-boot-and-trusted-execution`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Boot log: a signature verification failure, which is the control firing on a modified image.
- Device attestation: a boot measurement that does not match the signed manifest, which is the chain reporting a mismatch.
- Manufacturing audit: a unit whose OTP key hash matches the development key, which is the PKfail check.
- Firmware update log: an update accepted without a signature verification event.
- Recovery event: a recovery boot that did not record a verification, which is the unverified-path signal.
- Vulnerability intelligence: a bootloader or firmware vendor version named in a secure-boot advisory.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
