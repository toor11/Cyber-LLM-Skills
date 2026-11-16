---
name: container-escape-privileged-and-capabilities
description: Privileged containers and capability abuse. Covers escaping privileged containers and abusing dangerous capabilities such as SYS_ADMIN and SYS_PTRACE. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: cloud-container-supply-chain
tier: leaf
triggers: ["privileged container escape", "cap_sys_admin", "capability escape"]
cwe: [CWE-269]
owasp: []
attack: [T1611]
capec: [CAPEC-233]
related: [container-escape, container-escape-mount-and-socket-escapes, cloud-recon-and-enumeration, aws-attacks]
parent: container-escape
---

# Container Escape Privileged and Capabilities - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`hardening-cloud-and-containers`](../../../blue-team/vulnerability-and-hardening/hardening-cloud-and-containers/SKILL.md)

## Mechanism and Preconditions

Capabilities turn one namespace boundary into many fine-grained ones, and the security-relevant subset is small. `CAP_SYS_ADMIN` is the widest: it permits `mount`, `umount`, `pivot_root`, `setns` on some namespaces, BPF map creation, and a long tail that makes it effectively equivalent to root in most container configurations. `CAP_DAC_READ_SEARCH` bypasses file read permission checks, which reaches `/etc/shadow` and any host file that is mounted. `CAP_DAC_OVERRIDE` bypasses write checks. `CAP_SYS_PTRACE` allows `ptrace` of processes in the same PID namespace, which reaches secrets in memory. `CAP_SYS_MODULE` loads kernel modules, which is total control. `CAP_NET_ADMIN` reconfigures interfaces and iptables inside the shared network namespace. The review question is not whether the container is root — root without capabilities is far less dangerous than a non-root process with `CAP_SYS_ADMIN` — but which of these are in the effective set and whether a path exists to use them. The `privileged` flag sets all of them and is analysed in [`container-escape`](../container-escape/SKILL.md); this skill is the deliberate and accidental capability grants.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the effective set includes `CAP_SYS_ADMIN` **THEN** treat it as host root for analysis and say so; the mount path is available.
2. **IF** the effective set includes `CAP_SYS_MODULE` or `CAP_SYS_RAWIO` **THEN** it is total control regardless of every other control.
3. **IF** the set includes `CAP_DAC_READ_SEARCH` and any host path is mounted **THEN** the finding is the combination; either alone is weaker.
4. **IF** the container is non-root with a dropped set **THEN** verify with `capsh --print` inside, because the image can re-add capabilities through file capabilities.
5. **IF** the question is a host path or runtime socket **THEN** switch to [`container-escape-mount-and-socket-escapes`](../container-escape-mount-and-socket-escapes/SKILL.md).
6. **IF** the cluster enforces the `restricted` Pod Security Standard **THEN** all added capabilities are denied, which is the control; confirm the label is present and enforced.
7. **IF** the effective and bounding sets are empty and `allowPrivilegeEscalation` is false **THEN** record `Verified Safe` with the `capsh` output.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`container-escape`](../container-escape/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the effective set, not the declared one.** `capsh --print` inside the container shows what the process actually holds, including capabilities re-added by file capabilities on a binary.
2. **Classify each capability against the escape table.** `SYS_ADMIN`, `SYS_MODULE`, `SYS_RAWIO`, `DAC_READ_SEARCH`, `DAC_OVERRIDE`, `SYS_PTRACE`, and `NET_ADMIN` are the ones that cross a boundary; the rest are usually application needs.
3. **Choose the branch.** Deliberate grant in the manifest, implicit grant through `privileged`, or re-addition through file capabilities or a setuid binary.
4. **Define the baseline-vs-probe differential.** Baseline: the container as configured, `capsh --print` and a read of a host path it should not see. Probe: the same after dropping all capabilities, which should fail. A probe that succeeds where the baseline also succeeds means the capability is not the operative control and the finding is wrong.
5. **Name the stop condition.** Stop at the first host file read or mount that succeeds with the capability set present. Do not load a module or mount a device.
6. **State the proof.** Report the capability, how it got there, the operation it enabled, and the file or mount that was reachable. If the set is empty, record the negative with the `capsh` output and the `allowPrivilegeEscalation` value.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `CapEff` containing `cap_sys_admin` | Mount and namespace reach, which is enough for a host filesystem path | `capsh --print`, `/proc/self/status` |
| `capabilities.add: ["SYS_PTRACE"]` in a pod spec | Memory read of any process in the namespace, which reaches secrets | Pod specs, compose files |
| `getcap /usr/bin/python3` returning `cap_dac_read_search+ep` | A capability re-added by the image, invisible in the manifest | Filesystem capabilities |
| A setuid binary inside the image with a capability | Escalation path that survives a dropped bounding set | Image contents |
| `allowPrivilegeEscalation: false` with `drop: ["ALL"]` | The control: no setuid escalation and no capability to use | Pod security context |
| `CapBnd` empty | The bounding set prevents any re-acquisition, which is stronger than dropping from effective | `capsh --print` |

## Worked Contrast

**Vulnerable: non-root container carrying SYS_ADMIN and a file capability**

```dockerfile
# The run stage drops to a non-root user, which looks safe, but SYS_ADMIN is added
# at runtime and the image also carries a file capability on a helper binary.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 \
 && setcap cap_dac_read_search+ep /usr/bin/python3
USER 10001
ENTRYPOINT ["/usr/bin/python3", "/app/main.py"]
```

```yaml
# deployment fragment
securityContext:
  runAsNonRoot: true
  capabilities:
    add: ["SYS_ADMIN"]        # non-root, but effectively root
```

**Hardened: empty capability sets, no file capabilities, no privilege escalation**

```dockerfile
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 \
 && getcap -r / 2>/dev/null | awk '{print $1}' | xargs -r setcap -r
USER 10001
ENTRYPOINT ["/usr/bin/python3", "/app/main.py"]
```

```yaml
securityContext:
  runAsNonRoot: true
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault
```

**Why this matters:** The left container looks safe because it is non-root, but `SYS_ADMIN` gives it mount reach and the file capability gives it read access to any file regardless of permissions, so both together are a host read path. The right container has an empty effective and bounding set, cannot escalate through setuid, and has a syscall filter, so there is no capability to use and no way to acquire one.

## When It Is NOT This Issue

- **`CAP_NET_BIND_SERVICE` for a service on port 80 or 443.** The one capability applications legitimately need.
- **`CAP_CHOWN` or `CAP_SETUID` for an entrypoint that drops privileges at startup.** Common and defensible; the finding would need the capability to persist after the drop.
- **A non-root container with `allowPrivilegeEscalation: true` but a setuid-free image.** No escalation path exists inside; check the image before filing.
- **`CAP_SYS_PTRACE` in a debug sidecar restricted to its own pod's PID namespace.** Nothing outside the pod is reachable.
- **An empty `CapEff` with a populated `CapBnd`.** The process holds nothing now; the bounding set matters only if something can re-acquire.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `container-escape-privileged-and-capabilities` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `container-escape-privileged-and-capabilities` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: container-escape-privileged-and-capabilities
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1611]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`hardening-cloud-and-containers`](../../../blue-team/vulnerability-and-hardening/hardening-cloud-and-containers/SKILL.md) - Blue Detection/Defense Counterpart
- [`container-escape`](../container-escape/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`container-escape-mount-and-socket-escapes`](../container-escape-mount-and-socket-escapes/SKILL.md) - Cloud, Container and Supply Chain (leaf)
- [`cloud-recon-and-enumeration`](../cloud-recon-and-enumeration/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`aws-attacks`](../aws-attacks/SKILL.md) - Cloud, Container and Supply Chain (flagship)
- [`azure-and-entra-attacks`](../azure-and-entra-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `container-escape-privileged-and-capabilities` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1611`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/expku (3), CYBER_CPT/github_security_md (2), CYBER_CPT/ctf_search (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
