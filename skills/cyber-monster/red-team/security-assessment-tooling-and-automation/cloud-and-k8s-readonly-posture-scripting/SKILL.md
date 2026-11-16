---
name: cloud-and-k8s-readonly-posture-scripting
description: "Develops read-only cloud and Kubernetes security posture auditors using `boto3`, Azure SDK, and the Kubernetes Python client: paginating IAM policies, public bucket ACLs, security-group ingress, and PodSecurity/RBAC bindings with strict read-only credential checks and CIS/JSONL findings output. Use when writing custom CSPM or K8s audit scripts."
family: security-assessment-tooling-and-automation
tier: core
triggers: ["boto3 security audit", "k8s rbac audit script", "custom cspm python", "readonly cloud checker"]
cwe: [CWE-269]
owasp: []
attack: []
capec: []
related: [nuclei-template-engineering, nmap-nse-audit-script-authoring, burp-montoya-and-jython-extension-development, mitmproxy-addon-scripting]
corpus_sparse: true
---


# Cloud and K8s Readonly Posture Scripting - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **core** | Paired Counterpart: [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Read-only posture collection across a cloud account and a Kubernetes cluster: enumerate identities, roles, policies, workloads, and network exposure, then compare the collected state against a written baseline. Every call is a list or get operation; the discipline is that the script must fail closed when it lacks a permission rather than silently reporting a clean posture.

- **Absence of a result is not absence of a resource.** A `get_paginator` that raises AccessDenied produces an empty list; posture claims must distinguish *not present* from *not visible*.
- **Read-only is an IAM property, not a script property.** Use a role scoped to read verbs (or a readonly ClusterRole) so a coding mistake cannot mutate state.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a collector call raises AccessDenied **THEN** record the gap in the output and mark the posture result incomplete instead of skipping the resource type.
2. **IF** the cluster uses aggregated ClusterRoles **THEN** resolve the aggregation before asserting that a permission is absent.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a read-only credential, a baseline document, and a list of resource types the credential can actually see — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** boto3 with `get_paginator` and an explicit read-only session, kubernetes Python client (`rbac_v1.list_cluster_role_binding`, `list_namespaced_pod`)
- **Mandatory Self-Validation Command:** `python -c "import boto3, kubernetes; print(boto3.__version__, kubernetes.__version__)"`

1. Confirm the target surface: enumerate which accounts, regions, and namespaces are in scope, and record the identity used for collection.
2. Choose the branch: identity posture (users, roles, trust policies), network posture (security groups, ingress rules), or workload posture (service accounts, privileged pods, hostPath mounts).
3. Define the differential: the baseline is the approved configuration, the probe is the live account; a finding is a property present in live and absent from baseline, evaluated with the same query.
4. Name the stop condition: a resource-type list and a per-account page limit, so the run finishes inside the collection window and its coverage is known.
5. Prove it: every row carries the ARN or resource UID, the API call that produced it, and the timestamp, so a reviewer can re-issue the same read.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `session.client("iam").get_paginator("list_roles")` | Paginated read that returns complete role inventory; a single call truncates and understates exposure. |
| `rbac_v1.list_cluster_role_binding()` | Enumerates cluster-wide grants, the unit in which over-broad Kubernetes permissions actually appear. |
| `spec.containers[].securityContext.privileged` | Workload flag that turns a container into a node-level capability; a boolean and therefore cheap to baseline. |
| `spec.volumes[].hostPath` | Node filesystem exposure, which is a posture finding independent of the image. |

## Worked Contrast

**Collector That Swallows Permission Errors:**

```python
import boto3

s3 = boto3.client("s3")
try:
    buckets = s3.list_buckets()["Buckets"]
except Exception:
    buckets = []  # BUG: AccessDenied becomes "no public buckets", a false clean posture
print("public buckets:", [b for b in buckets if is_public(b)])
```

**Fail-Closed Collector With Explicit Coverage:**

```python
import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
rows, gaps = [], []
try:
    for page in s3.get_paginator("list_buckets").paginate():
        for b in page.get("Buckets", []):
            rows.append({"bucket": b["Name"], "created": b["CreationDate"].isoformat()})
except ClientError as exc:
    gaps.append({"call": "s3:ListBuckets", "error": exc.response["Error"]["Code"]})

print({"collected": len(rows), "gaps": gaps})
```

**Why this matters:** The difference between *there are no public buckets* and *I was not allowed to look* decides whether the report is accurate. Recording the gap keeps the posture claim honest and tells the engagement owner which additional read permission would complete the picture.

## When It Is NOT This Issue

- **AccessDenied read as a clean result.** The most common false negative in posture work; the resource was never observed.
- **Default security group counted as exposure.** A default group with no rules attached to an instance grants nothing; require an attached resource.
- **Aggregated ClusterRole read as empty.** The aggregation controller fills rules at admission; an unresolved aggregation looks like a missing permission.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER execute network or target checks without verifying the target against an explicit `--scope-file` allowlist.
- NEVER run unbounded concurrency, infinite retries, or state-mutating/destructive requests.
- NEVER hallucinate deprecated wrapper methods around `boto3.Session` — pin exact imports and handle exceptions explicitly.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `cloud-and-k8s-readonly-posture-scripting` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: cloud-and-k8s-readonly-posture-scripting
- **Target Stack & Schema**: Python 3.11+ typed CLI (`argparse`, bounded timeouts, scope allowlist, key API: `boto3.Session`)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile cloud_and_k8s_readonly.py; python cloud_and_k8s_readonly.py --help`
```

## Related Sub-Skills

- [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `cloud-and-k8s-readonly-posture-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
