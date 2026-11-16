# Detection Signals and Blue-Team Handoff

> Sub-skill: [`active-directory-certificate-services-esc1-through-esc4`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Certificate services event 4886 with `Template` naming a client-auth template and a `Requester` outside the expected group.
- Certificate services event 4887 for a denied request, which is what a remediated template produces for a SAN-supplied request.
- Windows Security 4768 with `PreAuthType 16` shortly after a 4886, the certificate-to-TGT sequence.
- Windows Security 5136 for changes to `pKICertificateTemplate` attributes, including `msPKI-Certificate-Name-Flag`.
- Directory diagnostic 1644 for bulk reads of the certificate templates container, the ESC discovery pattern.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`hardening-windows-and-ad-privileged-access-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-privileged-access-hardening/SKILL.md) | Query authoring, triage logic, and hardening verification |
