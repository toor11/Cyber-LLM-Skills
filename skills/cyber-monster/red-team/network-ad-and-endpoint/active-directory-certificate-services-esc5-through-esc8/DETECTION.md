# Detection Signals and Blue-Team Handoff

> Sub-skill: [`active-directory-certificate-services-esc5-through-esc8`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Certificate services event 4886 with `Requester` equal to a machine account that should never enroll, the ESC8 signature.
- Certificate services event 4899 or 4900 for a CA security or configuration change, which records ESC5 and ESC6 modification.
- IIS logs on the CA host showing POST to `/certsrv/certfnsh.asp` from an internal address outside the management subnet.
- Windows Security 4624 logon type 3 with `Package Name: NTLM` on the CA host from a computer account, the relayed authentication.
- Certificate services event 4887 for a denied request immediately after a coerced authentication, which shows EPA doing its job.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`hardening-windows-and-ad-privileged-access-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-privileged-access-hardening/SKILL.md) | Query authoring, triage logic, and hardening verification |
