# Verification Probes and Expected Differentials

> Sub-skill: [`ebpf-and-cilium-kubernetes-network-policy-audit`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Direction coverage per namespace

```text
# For each namespace: are both directions covered?
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  ing=$(kubectl get networkpolicy -n "$ns" -o json | jq '[.items[] | select(.spec.policyTypes|index("Ingress"))] | length')
  egr=$(kubectl get networkpolicy -n "$ns" -o json | jq '[.items[] | select(.spec.policyTypes|index("Egress"))] | length')
  printf '%-30s ingress=%s egress=%s\n' "$ns" "$ing" "$egr"
done
```

Expected differential: `egress=0` in a namespace that holds workloads is the finding; both non-zero is the control, and the counts tell you which namespaces to read next.

## Class 2 — Datapath and version

```text
kubectl -n kube-system get ds cilium -o jsonpath='{.spec.template.spec.containers[0].image}'
cilium config get enable-per-endpoint-routing bpf-host-routing enable-tcx 2>/dev/null
helm get values cilium -n kube-system -o yaml | rg -n "hostRouting|endpointRoutes|tcx"
```

Expected differential: a patched version with `hostRouting: true` is the control; a version in an advisory range with `hostRouting: false` and `endpointRoutes.enabled: true` is the finding, and the values are the citation.

## Class 3 — Reachability probe

```text
# From a lab pod in the namespace: does a connection the policy should deny succeed?
kubectl -n payments run probe --rm -it --image=busybox --restart=Never -- \
  sh -c 'nc -z -w2 kubernetes.default.svc 443 && echo "API REACHABLE"; nc -z -w2 169.254.169.254 80 && echo "METADATA REACHABLE"'
```

Expected differential: both connections failing is the control; either succeeding proves the open direction without any exploitation.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
