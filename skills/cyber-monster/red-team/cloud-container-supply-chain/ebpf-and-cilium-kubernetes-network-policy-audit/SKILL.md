---
name: ebpf-and-cilium-kubernetes-network-policy-audit
description: "Reviews Kubernetes NetworkPolicy and Cilium eBPF L3/L4/L7 policies: missing default-deny ingress/egress posture, DNS egress (`kube-dns` UDP/TCP 53) tunneling gaps, node-local metadata (`169.254.169.254`) egress blocks, and namespace label spoofing. Use when auditing cluster network isolation."
family: cloud-container-supply-chain
tier: leaf
triggers: ["kubernetes networkpolicy audit", "ciliumnetworkpolicy", "default deny k8s", "imds egress block k8s"]
cwe: [CWE-284]
owasp: []
attack: []
capec: []
related: [cloud-recon-and-enumeration, aws-attacks, azure-and-entra-attacks, gcp-attacks]
corpus_sparse: true
---

# EBPF and Cilium Kubernetes Network Policy Audit - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

eBPF-based network policy review has two layers that fail differently. The policy layer: a Kubernetes `NetworkPolicy` selects pods by label and declares ingress and egress rules, and its semantics are allow-only per direction — a pod selected by any policy for ingress has all ingress denied except what the rules permit, but a pod with no egress policy has unrestricted egress. That asymmetry is the single most common finding: a manifest that declares only `Ingress` reads as "locked down" and leaves all outbound traffic open. Cilium adds `CiliumNetworkPolicy` with L7 rules, and its enforcement depends on the datapath configuration — per-endpoint routing, BPF host routing, and TCX attachment all change which paths are covered. The 2025-2026 Cilium advisories are the concrete demonstration: a same-node L7 policy bypass when per-endpoint routing was enabled and BPF host routing disabled (the default in ENI-based EKS deployments), an ingress host and L7 policy bypass on nodes attached to both a VLAN interface and its parent with TCX enabled, and a path traversal in L7 secret references. The review question is therefore both "what does the policy say" and "which paths does the datapath actually cover".

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a namespace has ingress policies but no egress policies **THEN** egress is unrestricted, which is the finding; the asymmetry is in the policy model, not a bug.
2. **IF** the CNI is Cilium **THEN** record the version against the advisories and the datapath settings (`enable-per-endpoint-routing`, `bpf-host-routing`, `enable-tcx`) that determine coverage.
3. **IF** an L7 policy references a secret by name **THEN** check the Cilium version for the path-traversal advisory; the fix is a patch level.
4. **IF** the cluster is in ENI mode on EKS **THEN** per-endpoint routing is likely enabled, which is the configuration named in the same-node L7 bypass advisory.
5. **IF** the question is whether a pod can reach the API server **THEN** the branch is egress policy for the API server endpoint, which most clusters leave open.
6. **IF** the question is pod-level privilege rather than network reach **THEN** start at [`kubernetes-pentesting-admission-and-workload-abuse`](../kubernetes-pentesting-admission-and-workload-abuse/SKILL.md).
7. **IF** every namespace has both ingress and egress default-deny policies, the Cilium version is patched, and the datapath settings match the advisory-safe set **THEN** record `Verified Safe` with all three.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Inventory policies per direction.** For each namespace, the ingress policies and the egress policies, with their `podSelector` and `policyTypes`. A policy with only `Ingress` in `policyTypes` says nothing about egress.
2. **Read the datapath settings.** The CNI in use, its version, and the routing and attachment flags that determine which traffic paths are covered.
3. **Choose the branch.** Missing egress policy, L7 rule referencing a secret, datapath bypass, or version against an advisory.
4. **Define the baseline-vs-probe differential.** Baseline: a connection from a pod to an address the policy should deny. Probe: the same connection to an address the policy allows, or from a pod outside the selector. A baseline that succeeds is the finding, and it needs no exploitation — one `nc` or `curl` from a lab pod is enough.
5. **Name the stop condition.** Stop at the first denied-by-policy-intent connection that succeeds. Do not scan a cluster.
6. **State the proof.** Report the namespace, the policy set, the direction that is open, the datapath setting if relevant, and the exact connection that succeeded. If both directions are default-deny and the version is patched, record the negative with the policy list.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| A `NetworkPolicy` with `policyTypes: ["Ingress"]` only | Egress is unrestricted, so a compromised pod reaches anything routable | Kubernetes NetworkPolicy |
| No policy in a namespace with a `default-deny` name | The name suggests a control the manifest does not implement | Namespace policy set |
| A `CiliumNetworkPolicy` with an L7 `http` rule and a `secret` reference | The path-traversal advisory surface; version-dependent | Cilium 1.18/1.19/1.20 ranges |
| `enable-per-endpoint-routing: true` with `bpf-host-routing: false` | The datapath configuration named in the same-node L7 bypass advisory | Cilium Helm values |
| `enable-tcx: true` on nodes with a VLAN interface and its parent | The VLAN attachment configuration named in the ingress/L7 bypass advisory | Cilium agent flags |
| Both ingress and egress default-deny policies per namespace | The control: both directions are closed except what is declared | Namespace policy set |

## Worked Contrast

**Vulnerable: ingress-only policy set on an unpatched Cilium with the bypass datapath**

```yaml
# The only policy in the namespace, and it declares Ingress only — egress stays open.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: payments
spec:
  podSelector: {}
  policyTypes: ["Ingress"]
  ingress: []
```

```yaml
# Cilium values: per-endpoint routing on, BPF host routing off — the configuration
# named in the same-node L7 bypass advisory, on a version below the patched set.
routingMode: native
enableIPv4Masquerade: true
bpf:
  hostRouting: false
endpointRoutes:
  enabled: true
```

**Hardened: both directions denied by default, patched Cilium, and the advisory-safe datapath**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: payments
spec:
  podSelector: {}
  policyTypes: ["Ingress", "Egress"]
  ingress: []
  egress: []
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-api-egress
  namespace: payments
spec:
  podSelector:
    matchLabels: {app: payments-api}
  policyTypes: ["Egress"]
  egress:
    - to:
        - namespaceSelector:
            matchLabels: {kubernetes.io/metadata.name: payments-db}
      ports:
        - port: 5432
          protocol: TCP
```

```yaml
# Cilium at a patched release with BPF host routing enabled.
bpf:
  hostRouting: true
endpointRoutes:
  enabled: true
```

**Why this matters:** The left policy set denies ingress and leaves egress wide open, so a compromised pod can reach the API server, the metadata endpoint, and every other namespace; the datapath settings additionally match a published bypass, so even the ingress rule is not reliably enforced on same-node or VLAN-attached traffic. The right set denies both directions and allows exactly one egress path to the database, on a patched release with the datapath configured so the policy is actually applied.

## When It Is NOT This Issue

- **A namespace whose egress is restricted by a `CiliumNetworkPolicy` rather than a `NetworkPolicy`.** Check both policy types before filing.
- **A pod with no policy in a namespace where a cluster-wide default-deny selects everything.** The `podSelector: {}` in the cluster policy covers it.
- **An L7 policy with no secret reference.** The path-traversal advisory needs the secret field.
- **A Cilium version affected by an advisory but with the vulnerable feature disabled.** State the feature flag and close it.
- **Egress to a DNS server allowed from every pod.** Necessary for name resolution; the finding would be an unrestricted egress rule, not the DNS one.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ebpf-and-cilium-kubernetes-network-policy-audit` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ebpf-and-cilium-kubernetes-network-policy-audit` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ebpf-and-cilium-kubernetes-network-policy-audit
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-284 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md) - Blue Detection/Defense Counterpart
- [`cloud-recon-and-enumeration`](../cloud-recon-and-enumeration/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`aws-attacks`](../aws-attacks/SKILL.md) - Cloud, Container and Supply Chain (flagship)
- [`azure-and-entra-attacks`](../azure-and-entra-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`gcp-attacks`](../gcp-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`cloud-iam-privilege-escalation`](../cloud-iam-privilege-escalation/SKILL.md) - Cloud, Container and Supply Chain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ebpf-and-cilium-kubernetes-network-policy-audit` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
