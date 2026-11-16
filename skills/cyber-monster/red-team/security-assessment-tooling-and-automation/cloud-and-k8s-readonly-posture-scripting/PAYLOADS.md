# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`cloud-and-k8s-readonly-posture-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `cloud-and-k8s-readonly-posture-scripting`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Identity inventory baseline

Baseline: the approved role list from the baseline document. Probe: the live role list. Differential: roles present live with no baseline entry, or baseline roles with widened trust policies.

```bash
aws iam list-roles --query 'Roles[].{name:RoleName,arn:Arn}' --output json
aws iam get-role --role-name target-role --query 'Role.AssumeRolePolicyDocument'
```

## Cluster posture read

Baseline: an approved manifest set. Probe: live cluster objects. Differential: privileged containers or hostPath volumes with no baseline counterpart.

```bash
kubectl get clusterrolebinding -o json
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}'
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
