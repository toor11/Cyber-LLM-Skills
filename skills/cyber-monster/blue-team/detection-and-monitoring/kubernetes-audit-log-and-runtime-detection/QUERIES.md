# Detection Queries and Telemetry Artifacts

> Sub-skill: [`kubernetes-audit-log-and-runtime-detection`](SKILL.md) | Family: **Detection and Monitoring**

Audit-log and runtime queries owned by `kubernetes-audit-log-and-runtime-detection`. Field names follow the upstream `audit.k8s.io` event structure; confirm the mapping your shipper applies (`objectRef.namespace` versus a flattened `namespace`) before deploying. Every class states the expected hit and the false-positive note that must be cleared first.

## Class 1 — Coverage and policy ceiling (run before any other class)

Expected hit: at least one row per `stage` and `verb` you intend to rely on, and a `requestObject`-bearing stage present if any later class reads pod specs. Absence of `Request` here invalidates every spec-based query below.

```kql
KubeAudit_CL
| where TimeGenerated > ago(3d)
| summarize events=count(), objs=countif(isnotempty(ObjectRefResource_s)) by Stage_s, Level_s, verb_s
| sort by events desc
```

False-positive note: a cluster whose policy is `Metadata` legitimately has no `requestObject`; do not treat that as an ingestion failure, treat it as the documented ceiling and move the spec rules to `Inconclusive`.

## Class 2 — Interactive subresource access

Expected hit: `exec`, `attach` or `portforward` creates against named pods by a small set of principals. Any principal outside the operator baseline is a candidate.

```kql
KubeAudit_CL
| where TimeGenerated between (ago(1d) .. now())
| where verb_s == "create" and ObjectRefSubresource_s in ("exec", "attach", "portforward")
| project TimeGenerated, UserUsername_s, ObjectRefNamespace_s, ObjectRefName_s, SourceIPs_s, ResponseStatusCode_d
| sort by TimeGenerated desc
```

False-positive note: `kubectl debug` ephemeral containers and platform health checks produce the same verb; the exclusion key is `UserUsername_s`, not namespace.

## Class 3 — RBAC escalation surface

Expected hit: `create` or `patch` on `clusterrolebindings` or `roles`/`rolebindings` by a human principal, with the binding subject named in the body when policy allows. Controller-managed bindings repeat the same subject every reconcile.

```kql
KubeAudit_CL
| where verb_s in ("create", "patch", "update")
| where ObjectRefResource_s in ("clusterrolebindings", "rolebindings")
| extend subj = tostring(RequestObject_subjects[0].name)
| summarize grants=count(), roles=make_set(ObjectRefName_s, 10) by UserUsername_s, subj
| where grants > 0
| order by grants desc
```

False-positive note: a GitOps controller recreates the same binding on every sync, so a per-hour spike can be pure reconciliation; require a novel `subj` value before escalating.

## Class 4 — Identity anomalies and anonymous acceptance

Expected hit: requests from `system:anonymous` or group `system:unauthenticated` that returned a success code against a non-discovery resource. Success on `secrets`, `pods` or RBAC is the finding.

```kql
KubeAudit_CL
| where UserUsername_s == "system:anonymous" or UserGroups_s has "system:unauthenticated"
| where ResponseStatusCode_d < 400
| where ObjectRefResource_s !in ("", "selfsubjectaccessreviews", "selfsubjectrulesreviews")
| project TimeGenerated, verb_s, ObjectRefResource_s, ObjectRefNamespace_s, ResponseStatusCode_d, SourceIPs_s
```

False-positive note: anonymous `get` on `/version`, `/healthz` and discovery endpoints succeeds by design on clusters that left anonymous auth enabled; scope by resource, not by identity alone.

## Class 5 — Runtime divergence (Falco k8saudit and Tetragon)

Expected hit: a Falco alert carrying the same `ka.auditid` as the API event, or a Tetragon process event inside a container with no audit `exec` for that pod in the same minute. Divergence is the high-signal case.

```text
# Falco rule skeleton — k8saudit plugin source
- rule: Interactive shell in production namespace
  desc: exec or attach accepted against a pod in a prod namespace
  condition: >
    ka.verb = create and ka.target.subresource in (exec, attach)
    and ka.target.namespace in (prod-payments, prod-identity)
    and not ka.user.name startswith "system:serviceaccount:platform:"
  output: >
    Shell into pod (user=%ka.user.name pod=%ka.target.name ns=%ka.target.namespace
    src=%ka.sourceips audit=%ka.auditid)
  priority: WARNING
  source: k8saudit
  tags: [k8s, T1609]
```

```bash
# Tetragon: confirm process exec events are flowing for a namespace before trusting absence
kubectl exec -n kube-system ds/tetragon -- tetra getevents -o compact --pods prod-payments
```

False-positive note: Falco's own health probes and the Tetragon agent's own execs appear in these streams; filter by namespace ownership before concluding a payload ran.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the audit policy level and runtime sensor coverage beside every rule; a reviewer must be able to tell whether a zero was measured or assumed.
