# Operational Triage and Response Playbook

> Sub-skill: [`usb-and-peripheral-forensics`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `usb-and-peripheral-forensics`. Paired offensive/mechanics reference: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `usb forensics`.
- Alert, hunt outlier, or review request matching `removable media forensics`.
- Alert, hunt outlier, or review request matching `device history`.
- DLP or a badge system places a person at a host at a time and removable media is suspected.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| `USBSTOR` instance with a hardware serial, last-arrival inside the window, and a matching LNK or journal record for a path on that volume | Confirmed Removable-Media Access | Preserve the hive set and the LNK/journal output; acquire the physical device under evidence handling before it is reused |
| `USBSTOR` instance with arrival and removal times but no file-access artefact | Attachment Only | Report attachment without a transfer claim; pivot to Sysmon 29, journal and shellbags for access evidence |
| Device appearing under `Enum\SCSI` only, with a matching `Enum\USB` serial | Normal UASP Device | Record the protocol and treat as ordinary storage; no concealment inference |
| `setupapi.dev.log` install time exactly one hour from the registry FILETIME | Time-Zone Artefact | Report both values with the conversion; do not describe a second install event |
| Instance ID with `&` as second character and no match on any peer host | Unmatchable Identifier | Do not claim cross-host device identity; restrict the finding to this host |

## Containment and Recovery

1. **Preserve before mutating:** collect the SYSTEM hive with its transaction logs, every per-user `NTUSER.DAT`, `setupapi.dev.log` with its archives, and the `Partition/Diagnostic` channel, then hash them.
2. **Recover the device, not just the record:** if the physical medium is identified, seize it under the case's evidence handling rules; the host artefacts prove attachment, the device proves content.
3. **Separate the time bases in the report:** UTC registry values and local PnP log values must appear in distinct fields, with the conversion stated, or a reviewer will recompute a phantom event.
4. **Check blast-radius allowlists:** never auto-isolate domain controllers, DNS, or core gateways without human approval.
