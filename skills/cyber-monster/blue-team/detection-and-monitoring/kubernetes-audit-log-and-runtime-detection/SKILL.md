---
name: kubernetes-audit-log-and-runtime-detection
description: "Detects cluster compromise via Kubernetes API Audit Logs and Falco/Tetragon eBPF runtime events: `pods/exec` and `pods/attach`, anonymous/system:unauthenticated calls, `ClusterRoleBinding` escalation, `secrets` list sweeps, and host-namespace pod creation. Use when monitoring Kubernetes control and data planes."
family: detection-and-monitoring
tier: core
triggers: ["kubernetes audit log detection", "falco rule k8s", "tetragon runtime", "pods exec detection"]
cwe: [CWE-778]
owasp: []
attack: []
capec: []
related: [detection-engineering, sigma-rule-authoring, yara-rule-authoring, siem-query-and-log-analysis]
corpus_sparse: true
---

# Kubernetes Audit Log and Runtime Detection - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Detection and Monitoring`](../README.md) | Tier: **core** | Paired Counterpart: [`kubernetes-pentesting`](../../../red-team/cloud-container-supply-chain/kubernetes-pentesting/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

The kube-apiserver emits one audit event per request and per configured stage, and the audit policy decides how much of that request is retained: a `Metadata`-level rule preserves `verb`, `objectRef`, `user` and `responseStatus` but drops `requestObject`, so any detection that reads the submitted pod spec or RoleBinding body silently returns zero rows on a `Metadata` cluster. `objectRef.subresource` is what separates a read of pods from an interactive `exec`, `attach` or `portforward` into a running workload, and `verb` distinguishes `create` on a `ClusterRoleBinding` from routine `get` traffic. Identity lives in `user.username` with `system:anonymous` and group `system:unauthenticated` marking requests that passed no authenticator. Audit logs record intent at the control plane only; the process that actually spawned inside the container appears in Falco syscall events (k8saudit plugin or eBPF driver) or Tetragon process events, and the two planes must be correlated on pod name plus timestamp.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the audit policy level for the affected resources is unknown or set to `None`/`Metadata` **THEN** establish the level first, and **IF** it is `Metadata` **THEN** drop every detection that inspects `requestObject` and report `INCONCLUSIVE (Telemetry Gap)` for spec-based rules.
2. **IF** the cluster is managed and the provider exposes only a filtered audit stream (no `RequestReceived` stage, no `requestObject`) **THEN** treat the control-plane branch as partial and lean on runtime telemetry for process-level proof.
3. **IF** the question is "who asked the API server to do this" **THEN** take the audit branch; **IF** the question is "what actually ran inside the container" **THEN** take the Falco/Tetragon branch; do not answer one with the other.
4. **IF** both stages are collected **THEN** de-duplicate on `auditID` before counting, because the same request appears as `RequestReceived` and `ResponseComplete`.
5. **IF** the target is a data-plane action (shell in a pod, file write under a mounted hostPath, outbound connection) **THEN** require a runtime event source; a clean audit log alone is not evidence of absence.
6. **IF** telemetry source covering `objectRef.subresource=exec` or `ClusterRoleBinding create` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`kubernetes-pentesting`](../../../red-team/cloud-container-supply-chain/kubernetes-pentesting/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Audit-field classes plus k8saudit/Falco coverage probes |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | `kubectl`, `jq`, `falco`, `tetra` invocation shapes |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Pod-level containment without breaking the control plane |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm which control-plane evidence actually exists.** Pull the audit policy in force and list the distinct `stage`, `verb` and `objectRef.resource` values present in the index for the window. If the index holds only `ResponseComplete` at `Metadata`, record that as the ceiling on every later step rather than working around it with regex on a missing field.
2. **Choose the branch by question type.** RBAC change, impersonation, secret read and exec *request* belong to the audit branch keyed on `verb` plus `objectRef`. Post-exploitation behaviour inside a workload — new child process, hostPath write, unexpected egress — belongs to the runtime branch keyed on pod and container identity. State the branch and its blind spot in the output.
3. **Define the baseline-versus-probe differential per principal.** For each `user.username`, compare the count of `create` on RBAC objects, `exec` subresources and `secrets` reads over a quiet 14-day window against the alert window. Score the per-principal delta, not the cluster-wide total, because a single noisy operator account dominates any aggregate.
4. **Name the stop condition.** Stop and declare `Inconclusive` when the audit policy is `Metadata` for the object in question, when the managed provider's retention ends inside the window, when the container was recreated so pod name plus UID no longer resolve, or when no runtime sensor covers the node. Do not downgrade these to "probably fine".
5. **State what counts as proof.** Proof is an audit event showing the initiating principal and object, plus a runtime event on the same node and pod within the same minute showing the process that resulted. A single `exec` audit event with no corresponding runtime process is a request, not an execution.

## Concrete Patterns

| Indicator / Artifact | Query class | What it proves |
|---|---|---|
| `verb=create` with `objectRef.resource=pods` and `objectRef.subresource=exec` | audit subresource | An interactive session was requested against a named pod by a named principal; on `Metadata` policy this is the strongest available evidence |
| `objectRef.resource=clusterrolebindings` and `verb in (create, patch)` | audit RBAC differential | A privilege grant was issued or widened; per-principal rarity against a 14-day baseline separates a one-off from the platform controller |
| `user.username=system:anonymous` with `responseStatus.code` below 400 | audit identity | The request was accepted without authentication, which on a hardened cluster should be limited to health and discovery paths |
| `objectRef.resource=secrets` with `verb=list` or `get` across many namespaces | audit enumeration | Bulk credential harvesting shape, distinct from a workload reading its own mounted secret |
| `hostPID`, `hostNetwork` or hostPath in `requestObject.spec` | audit spec inspection | The pod was created with node-level reach; requires `Request` or `RequestResponse` policy to be visible at all |
| Falco `k8saudit` rule firing on the same `auditID` as the API event | runtime correlation | The rule engine classified the same request as suspicious, giving an independent analytic on the control plane |
| Tetragon `process_exec` inside a container with no matching `exec` audit event | runtime divergence | A process started through a path the API server never saw — exec via runtime socket, cron inside the image, or a compromised workload |

## Worked Contrast

**Weak / Noisy Detection Practice:**

```text
index=kube_audit "exec"
| stats count by user.username
# Substring match: hits the word exec in any field, including namespace names,
# and an empty count is read as "no shells" even when the policy is Metadata.
```

**High-Signal Grounded Detection:**

```text
index=kube_audit sourcetype="kube:audit" stage=ResponseComplete verb=create
  objectRef.subresource IN (exec, attach, portforward)
| eval who=coalesce('user.username', "-")
| stats count AS c, dc(objectRef.name) AS pods, values(sourceIPs{}) AS srcs by who, objectRef.namespace
| eventstats avg(c) AS mu, stdev(c) AS sd by who
| where c > mu + (3*sd) OR pods > 2
| table who, objectRef.namespace, pods, c, srcs
```

**Why this matters:** the strong form pins `stage` so the request is not double counted, filters on the structured subresource rather than on raw text, and compares each principal to its own history so an interactive debug session stands out from an operator that execs constantly.

## When It Is NOT This Issue

- **Platform controllers and GitOps agents:** `replicaset-controller`, `cluster-autoscaler` and Argo/Flux service accounts create and patch RBAC and exec into pods continuously. Their `user.username` is the exclusion key; a namespace-based exclusion will mask a real compromise in the same namespace.
- **Debug and troubleshooting sessions:** `kubectl debug` and `kubectl exec` by on-call engineers are indistinguishable at the audit layer from an intruder's shell. The differentiator is the source identity and the change ticket, not the verb.
- **Anonymous discovery traffic:** with anonymous auth left enabled, `system:anonymous` performs `get` on `/version`, `/healthz` and discovery endpoints by design. Only anonymously *accepted* requests touching `secrets`, `pods` or RBAC are findings.
- **Stage and replica duplication:** the same request appears at `RequestReceived` and `ResponseComplete`, and HA control planes may forward from more than one API server, so raw counts double or triple without any adversary.
- **Managed-cluster audit truncation:** providers that ship a reduced audit stream drop `requestObject` and may sample high-volume verbs, so spec-based detections have no data while the cluster looks healthy.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `objectRef.subresource=exec` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER claim a container command executed when only the audit request was observed** — say "exec requested" and name the runtime source you still need.
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** the audit policy level and stage set were read from the cluster, and the runtime sensor coverage per node was enumerated, not assumed.
- [ ] **Branch and differential defined:** audit versus runtime was chosen explicitly, with a quiet-window baseline per principal to compare against.
- [ ] **Stop condition stated:** metadata-only policy, provider retention, pod UID churn and node sensor gaps were each cleared or named as the reason for `Inconclusive`.
- [ ] **Proof standard met:** an initiating principal from audit is paired with a runtime process on the same pod inside one minute, or the output says which half is missing.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: kubernetes-audit-log-and-runtime-detection
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`kubernetes-pentesting`](../../../red-team/cloud-container-supply-chain/kubernetes-pentesting/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`detection-engineering`](../detection-engineering/SKILL.md) - Detection and Monitoring (flagship)
- [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`yara-rule-authoring`](../yara-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) - Detection and Monitoring (core)
- [`log-source-onboarding-and-parsing`](../log-source-onboarding-and-parsing/SKILL.md) - Detection and Monitoring (core)

## Operating Notes

- **Two planes, two questions:** the audit log answers "who asked", runtime answers "what ran". Reporting one as the other is the most common error in this leaf.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; `kubectl` reads and `kubectl auth can-i` are safe, anything that mutates a workload is not.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
