---
name: container-escape-mount-and-socket-escapes
description: Mount and runtime socket escapes. Covers hostPath and bind mount escapes, exposed docker or containerd sockets, and cgroup release_agent paths. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: cloud-container-supply-chain
tier: leaf
triggers: ["docker socket escape", "hostpath escape", "cgroup escape"]
cwe: [CWE-269]
owasp: []
attack: [T1611]
capec: [CAPEC-233]
related: [container-escape, container-escape-privileged-and-capabilities, cloud-recon-and-enumeration, aws-attacks]
parent: container-escape
---

# Container Escape Mount and Socket Escapes - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`hardening-cloud-and-containers`](../../../blue-team/vulnerability-and-hardening/hardening-cloud-and-containers/SKILL.md)

## Mechanism and Preconditions

Mounts and sockets are the most common escape path because they are the most common convenience. A mounted `docker.sock` or `containerd.sock` is a complete API to the container runtime: `docker ps` from inside the container lists siblings, and `docker run -v /:/host --privileged` creates a container that owns the host. A mounted `/var/run/crio/crio.sock` or a CRI socket is the same. The `hostPath` variants are subtler: `/` mounted read-write is immediate; `/etc` allows writing `crontab`, `passwd`, or a systemd unit; `/var/lib/kubelet` reaches the kubelet's client certificate and the static pod manifests; `/proc` mounted from the host reaches kernel parameters. The mount namespace itself can be the vector when `CAP_SYS_ADMIN` allows a new bind mount of a host path, which is why the capability and the mount surface are analysed together. The 2025 runc advisories matter here specifically: masked-path abuse let a container replace `/dev/null` with a symlink so runc bind-mounted an arbitrary source read-write, which reached `/proc/sys/kernel/core_pattern` and from there host root — no host mount required in the manifest at all.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a runtime socket is mounted **THEN** the finding is complete: the container can start a privileged sibling, which is host root. No further analysis adds to it.
2. **IF** `/` or `/etc` is mounted read-write **THEN** the finding is the write path, and the specific file that grants execution decides severity.
3. **IF** `/var/lib/kubelet` is mounted **THEN** the kubelet client certificate is readable, which reaches the API server with node identity.
4. **IF** `/proc` is mounted from the host **THEN** kernel parameters are writable with the right capability; check `CAP_SYS_ADMIN` alongside.
5. **IF** the runtime version predates the masked-path fixes and the container uses custom mounts **THEN** the escape needs no host mount; cite the version.
6. **IF** the question is capabilities rather than mounts **THEN** switch to [`container-escape-privileged-and-capabilities`](../container-escape-privileged-and-capabilities/SKILL.md).
7. **IF** no socket and no host path is mounted and the runtime is patched **THEN** record `Verified Safe` with the volume list and the runtime version.

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

1. **Inventory every volume and socket.** `docker inspect` or `kubectl get pod -o json` gives the mounts; the host paths and the socket paths are the two lists that matter.
2. **Classify each mount.** Runtime socket (immediate), filesystem root or `/etc` read-write (immediate), kubelet directory (credential), `/proc` (kernel parameter), or a data directory (usually benign).
3. **Choose the branch.** Socket, host filesystem write, credential material, or runtime masked-path vulnerability.
4. **Define the baseline-vs-probe differential.** Baseline: `ls` of the mount target from inside the container, which shows what is reachable. Probe: a read of the specific file that matters for the branch — the socket's existence and type, the kubelet certificate's presence, or the writability of `/etc/passwd`. A read that succeeds where the design says it should not is the finding.
5. **Name the stop condition.** Stop at the first proof: a socket that answers a version request, a host file that reads, or a host file that is writable. Do not start a container or write to a host file.
6. **State the proof.** Report the mount source, the target, the operation that succeeded, and the file or API reached. If every mount is a data directory with no credentials and no socket, record the negative with the volume list.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `hostPath: /var/run/docker.sock` mounted into a container | Runtime API access, which creates privileged siblings on the host | Compose files, CI runners, Kubernetes pods |
| `hostPath: /` with no `readOnly: true` | Host filesystem write, so any file including a startup script is editable | Privileged DaemonSets, debug pods |
| `hostPath: /var/lib/kubelet` | Kubelet client certificate and static pod manifests, so node identity and pod injection | Node-level DaemonSets |
| `hostPath: /proc` from the host | Kernel parameters writable with `SYS_ADMIN`, including `core_pattern` | Debug containers |
| An `emptyDir` or a named volume with no host path | No host reach, which is the control | Ordinary workloads |
| runc below 1.2.8 with a custom `mounts:` entry | Masked-path abuse without a host mount in the manifest | Container runtime version |

## Worked Contrast

**Vulnerable: runtime socket and host root mounted read-write**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: ci-runner
spec:
  containers:
    - name: runner
      image: registry.example/ci:5.1
      volumeMounts:
        - name: docker
          mountPath: /var/run/docker.sock
        - name: host
          mountPath: /host
  volumes:
    - name: docker
      hostPath:
        path: /var/run/docker.sock
    - name: host
      hostPath:
        path: /
```

**Hardened: no runtime socket, workspace as an ephemeral volume, read-only where a mount is unavoidable**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: ci-runner
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: runner
      image: registry.example/ci:5.1
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      volumeMounts:
        - name: workspace
          mountPath: /workspace
        - name: cache
          mountPath: /cache
          readOnly: true
  volumes:
    - name: workspace
      emptyDir: {}
    - name: cache
      persistentVolumeClaim:
        claimName: builder-cache-ro
```

**Why this matters:** The left pod has two complete escapes — the runtime socket starts a privileged container, and the host root mount edits any file — so neither needs a vulnerability. The right pod has no socket, writes only to an ephemeral directory, reads a cache volume that is read-only, and has no capabilities, so there is no host path and no API to reach.

## When It Is NOT This Issue

- **An `emptyDir` or a PVC mount.** No host reach unless the CSI driver itself is a host path.
- **A `hostPath` of `/var/log` mounted read-only for a log shipper with no credentials inside.** Worth noting, not an escape path.
- **A `/var/run/docker.sock` mount on a node-level DaemonSet that manages containers by design.** The exposure is real; the argument is whether application workloads can reach that pod.
- **A read-only mount of a configuration file.** No write path, so no persistence.
- **A socket mount in a pod that runs no untrusted code and has no network exposure.** Severity is bounded by whether anything can execute there.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `container-escape-mount-and-socket-escapes` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `container-escape-mount-and-socket-escapes` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: container-escape-mount-and-socket-escapes
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1611]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`hardening-cloud-and-containers`](../../../blue-team/vulnerability-and-hardening/hardening-cloud-and-containers/SKILL.md) - Blue Detection/Defense Counterpart
- [`container-escape`](../container-escape/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`container-escape-privileged-and-capabilities`](../container-escape-privileged-and-capabilities/SKILL.md) - Cloud, Container and Supply Chain (leaf)
- [`cloud-recon-and-enumeration`](../cloud-recon-and-enumeration/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`aws-attacks`](../aws-attacks/SKILL.md) - Cloud, Container and Supply Chain (flagship)
- [`azure-and-entra-attacks`](../azure-and-entra-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `container-escape-mount-and-socket-escapes` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1611`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/github_security_md (2), CYBER_CPT/sigmahq (1), CYBER_CPT/gh_advisories (1), CYBER_CPT/go_exploitdb (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
