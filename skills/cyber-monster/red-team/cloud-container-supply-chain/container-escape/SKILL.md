---
name: container-escape
description: "Escapes container isolation: privileged containers, dangerous capabilities and mounts, exposed runtime sockets, and kernel-level escapes. Use when you have execution inside a container."
family: cloud-container-supply-chain
tier: core
triggers: ["container escape", "docker escape", "privileged container", "runtime socket escape"]
cwe: [CWE-269]
owasp: []
attack: [T1611]
capec: [CAPEC-233]
related: [container-escape-privileged-and-capabilities, container-escape-mount-and-socket-escapes, cloud-recon-and-enumeration, aws-attacks]
---

# Container Escape - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **core** | Paired Counterpart: [`hardening-cloud-and-containers`](../../../blue-team/vulnerability-and-hardening/hardening-cloud-and-containers/SKILL.md)

## Mechanism and Preconditions

A container is a set of namespaces and a set of controls around them, not a security boundary by itself. Escape review therefore asks which control is missing rather than which exploit exists. The privileged case is the simplest: `--privileged` grants every capability and every device, so the container can mount the host filesystem directly, and it is indistinguishable from host root for practical purposes. The capability case is narrower but still decisive: `CAP_SYS_ADMIN` allows mount, `pivot_root`, and BPF operations; `CAP_DAC_READ_SEARCH` allows opening any file regardless of permissions; `CAP_SYS_PTRACE` allows reading another process's memory. The namespace case is the host-shared one: `--pid=host` makes node processes visible and signalable, `--net=host` shares the node's network stack including its metadata endpoint access, and `--ipc=host` shares memory segments. The mount case is the exposed socket or path: `/var/run/docker.sock` or `containerd.sock` is a direct API to the runtime, and a `hostPath` of `/` or `/etc` reaches node configuration. The 2025 runc advisories (CVE-2025-31133, CVE-2025-52565, CVE-2025-52881, published together in November 2025 and fixed in 1.2.8, 1.3.3, and 1.4.0-rc.3) are a reminder that the runtime itself can be the missing control: masked-path abuse let a container bind-mount an arbitrary source, including `/proc/sys/kernel/core_pattern`, and gain host root regardless of configuration.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the container is `privileged` **THEN** treat it as host root and say so; no further capability analysis changes the conclusion.
2. **IF** the container has `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, or `CAP_DAC_READ_SEARCH` **THEN** switch to [`container-escape-privileged-and-capabilities`](../container-escape-privileged-and-capabilities/SKILL.md) for the specific analysis.
3. **IF** a runtime socket or a host path is mounted **THEN** switch to [`container-escape-mount-and-socket-escapes`](../container-escape-mount-and-socket-escapes/SKILL.md).
4. **IF** the container shares a host namespace **THEN** the relevant skill is the one matching the namespace: PID and process visibility here, network reachability in the cloud metadata skill.
5. **IF** the runtime version is below the current patch for its branch **THEN** record the version and the advisory class; masked-path abuse needs no misconfiguration at all.
6. **IF** the workload runs with a user namespace where host root is not mapped **THEN** the severity of most escapes drops sharply; state whether user namespaces are in use.
7. **IF** the container is unprivileged, has no added capabilities, mounts no host path, and shares no namespace **THEN** record `Verified Safe` with those four facts, because that is a complete argument.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `container-escape-privileged-and-capabilities` | [`container-escape-privileged-and-capabilities`](../container-escape-privileged-and-capabilities/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `container-escape-mount-and-socket-escapes` | [`container-escape-mount-and-socket-escapes`](../container-escape-mount-and-socket-escapes/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate the five control surfaces.** Privileged flag, capability set, namespace sharing, mounted sockets and paths, and runtime version. Each is independently sufficient; the report names the one that applies rather than a list.
2. **Check user-namespace status.** If host root is not mapped into the container's user namespace, most of the filesystem and device paths are blocked by DAC. This single fact changes severity more than any other.
3. **Choose the branch.** Privileged, capability, host namespace, mount or socket, or runtime vulnerability.
4. **Define the baseline-vs-probe differential.** Baseline: `capsh --print` and `/proc/self/status` inside the container, which show the capability set and the namespace inode numbers. Probe: the same on the host, or a comparison of namespace inodes — matching inodes prove sharing, which is the finding.
5. **Name the stop condition.** Stop at the first proof of host-level reach: a successful read of a host file, a matching namespace inode, or a runtime socket that answers. Do not perform a full escape.
6. **State the proof.** Report the field or flag, the namespace inode comparison or the file read, and the severity qualifier (user namespaces present or absent). If all five surfaces are clean, record the negative with the capability and namespace output.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `securityContext.privileged: true` | Every capability and device, which is host root for practical purposes | Pod specs, `docker run --privileged` |
| `CAP_SYS_ADMIN` in the effective set | Mount, pivot_root, and BPF reach, which is enough for a host filesystem path | Docker `--cap-add`, Kubernetes capabilities |
| `/proc/self/status` `NSpid` showing host pids | `hostPID`, so node processes are visible and signalable | Pod specs, compose files |
| A bind mount of `/var/run/docker.sock` | The runtime API, which creates sibling containers on the host | Compose files, CI runners |
| Matching namespace inodes between container and host | The definitive proof of sharing, stronger than any flag reading | `/proc/<pid>/ns/*` |
| runc below 1.2.8 with a container using custom mounts | Masked-path abuse without any misconfiguration | Container runtime on the node |

## Worked Contrast

**Vulnerable: privileged container with host namespaces and the runtime socket**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: build
spec:
  hostPID: true
  hostNetwork: true
  containers:
    - name: build
      image: docker:27-cli
      securityContext:
        privileged: true
      volumeMounts:
        - name: sock
          mountPath: /var/run/docker.sock
  volumes:
    - name: sock
      hostPath:
        path: /var/run/docker.sock
```

**Hardened: unprivileged, user namespaced, no host mounts, explicit capability drop**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: build
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: build
      image: registry.example/builder:3.2
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      volumeMounts:
        - name: workspace
          mountPath: /workspace
  volumes:
    - name: workspace
      emptyDir: {}
```

**Why this matters:** The left pod is a root shell on the node: privileged gives it every device, `hostPID` and `hostNetwork` remove two namespace boundaries, and the runtime socket lets it start another privileged container even if the first two were removed. The right pod is non-root, drops every capability, has no host mount, no token, and a read-only root, so none of the five surfaces is open.

## When It Is NOT This Issue

- **A privileged DaemonSet that the platform team owns and that application workloads cannot schedule onto.** The exposure is real but the reachability argument must be made.
- **`CAP_NET_BIND_SERVICE` alone.** Ports below 1024 are not a host boundary.
- **A `hostPath` mount of a read-only config file with no credentials.** Worth noting, but not an escape path.
- **A container running as root inside a user namespace where host root is not mapped.** Root in that namespace has no DAC over host files.
- **`hostNetwork: true` on a CNI plugin.** The plugin needs it by design; the finding is whether application pods can use the same setting.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `container-escape` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `container-escape` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: container-escape
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1611]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`hardening-cloud-and-containers`](../../../blue-team/vulnerability-and-hardening/hardening-cloud-and-containers/SKILL.md) - Blue Detection/Defense Counterpart
- [`container-escape-privileged-and-capabilities`](../container-escape-privileged-and-capabilities/SKILL.md) - Cloud, Container and Supply Chain (leaf)
- [`container-escape-mount-and-socket-escapes`](../container-escape-mount-and-socket-escapes/SKILL.md) - Cloud, Container and Supply Chain (leaf)
- [`cloud-recon-and-enumeration`](../cloud-recon-and-enumeration/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`aws-attacks`](../aws-attacks/SKILL.md) - Cloud, Container and Supply Chain (flagship)
- [`azure-and-entra-attacks`](../azure-and-entra-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `container-escape` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1611`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 15 |
| Distinct dataset sources | 8 |
| Top sources | CYBER_CPT/L5/ctf_search (3), CYBER_CPT/github_security_md (3), hackerone_disclosed_reports (2), CYBER_CPT/ctf_search (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 11 cases |
| Grounding | multi-dataset corpus-grounded |
