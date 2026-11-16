# Operational Triage and Response Playbook

> Sub-skill: [`memory-forensics`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `memory-forensics`. Paired offensive/mechanics reference: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

Memory is the only evidence that a containment action can destroy outright, and it is the layer where fileless activity lives. The runbook's rule is therefore absolute: capture before containment, capture to external media, and record the capture window — because every later claim about what ran, what connected and what credentials were in use depends on an image taken while those things still existed. The second rule is interpretive: memory yields candidates, not conclusions. `malfind` hits, scan-only processes and private executable regions are heuristics that become findings only when a second structure agrees.

## Triggers

- Alert, hunt outlier, or review request matching `memory forensics`.
- Alert, hunt outlier, or review request matching `volatility`.
- Alert, hunt outlier, or review request matching `ram analysis`.
- Alert, hunt outlier, or review request matching `memory dump analysis`.
- An EDR alert names injected code, a hidden process or a credential-access technique on a host that is still running.
- A host must be contained and the pre-containment state exists only in RAM.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Scanning plugin and a second structure agree on an unlinked process or injected region | Confirmed in-memory activity | Preserve the image and hash; hand the region content to the appropriate analysis skill, and scope the network endpoints it held |
| Image smeared across a long capture, structures disagree between plugins | Inconclusive (Smear) | Re-run with scanning counterparts, cross-check, and state the capture window in the report |
| Layer or symbol detection failed for the build | Inconclusive (Layer Failure) | Record the version and build, try a neighbouring Volatility release, and do not interpret plugin output |
| Pagefile and hibernation file not collected | Partial (Paged-out Content Unreachable) | State the limitation; scope credentials and connections from other sources |
| `malfind` hits only in JIT, browser or security-product processes | Benign Baseline (JIT Allocation) | Record the processes and exclude them; require content corroboration for any exception |
| Interactive desktop present on a server that should have none | Anomalous session | Preserve the session structures and scope the account and remote address |
| Host already contained before capture | Inconclusive (Post-containment State) | Say so explicitly; the image reflects the state after the responder's actions, not the malware's behaviour |

## Containment and Recovery

1. **Preserve before mutating:** capture memory first, to external or network storage, then hash it. Every subsequent action — isolation, an EDR scan, a service restart — overwrites free pages where terminated processes, closed connections and decrypted secrets still sit.
2. **Capture the pagefile and hibernation file too.** They are the only route to pages the OS evicted, and a RAM image without them cannot answer questions about older activity.
3. **Check blast-radius allowlists:** Never auto-isolate domain controllers, DNS, or core gateways without human approval — and never run an acquisition driver on a critical host without testing it on that build first, because a blue-screen during capture destroys the evidence and the service.
4. **Treat captured credentials as exposed:** if the image shows plaintext credentials, hashes or tokens, rotate them and revoke sessions. A memory image proves they were in memory; it does not prove they were not also exfiltrated.
5. **Eradicate root cause:** Patch or reconfigure the underlying weakness before restoring normal access. If the activity was fileless, the fix is a control on the execution path — script-block logging, AMSI, constrained language mode — not a file deletion that the next execution will bypass.
