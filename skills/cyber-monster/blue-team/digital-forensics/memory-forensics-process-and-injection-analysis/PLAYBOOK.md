# Operational Triage and Response Playbook

> Sub-skill: [`memory-forensics-process-and-injection-analysis`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `memory-forensics-process-and-injection-analysis`. Paired offensive/mechanics reference: [`process-injection-techniques`](../../../red-team/network-ad-and-endpoint/process-injection-techniques/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `memory injection detection`.
- Alert, hunt outlier, or review request matching `process hollowing memory`.
- Alert, hunt outlier, or review request matching `volatility process`.
- An EDR reports a remote-thread creation into a process that has no business being a target.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Mapped image in the VAD tree absent from the `InLoad` list, in a non-JIT process, with the on-disk binary of that path hashing differently from the mapped header | Confirmed Malicious | Preserve image and dump the hidden region; treat every credential resident in that process as disclosed |
| `malfind` RWX regions confined to a managed-runtime or browser host, matching the other instances of the same binary | Benign Baseline | Record the runtime class in the baseline note; suppress by process class rather than disabling the plugin |
| `psscan`-only PID with an exit time and no live thread | Normal Teardown | No action; note that pool residue is expected until reuse |
| Plugin name fails to resolve on a 2.26.2+ build | Inconclusive (Tool Gap) | Re-run under `windows.malware.*` before recording any negative finding |
| `processghosting` reports `DeletePending` on an image under a temp or user-writable path | Confirmed Malicious | Dump the image file object target before it is released; scope persistence in registry and scheduled tasks |

## Containment and Recovery

1. **Preserve before mutating:** hash the image, then dump the suspect region or ghosted image to a new directory. A process termination releases the pool pages this analysis depends on.
2. **Recover identity, not just evidence:** extract the mapped image header and hash from an independent copy so the finding survives the host being rebuilt.
3. **Rotate what the process could reach:** a process with injected code in a privileged context should be assumed to have touched every secret that context can read, including tokens and cached credentials.
4. **Check blast-radius allowlists:** never auto-isolate domain controllers, DNS, or core gateways without human approval.
