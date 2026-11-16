# Detection Signals and Blue-Team Handoff

> Sub-skill: [`active-directory-certificate-services`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Certificate services event 4886 for a certificate issued, with `Requester` and `Template` fields that show unexpected enrollment.
- Certificate services event 4887 for a certificate request denied, which records the CA enforcing its enrollment ACL.
- Windows Security 4768 with `PreAuthType 16` (PKINIT) on a domain controller, the moment a certificate becomes a TGT.
- Windows Security 5136 for a change to `pKICertificateTemplate` attributes, which is how a template becomes vulnerable.
- Directory diagnostic 1644 for high-volume reads of `CN=Certificate Templates`, the enumeration pattern that precedes ESC discovery.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`hardening-windows-and-ad-privileged-access-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-privileged-access-hardening/SKILL.md) | Query authoring, triage logic, and hardening verification |
