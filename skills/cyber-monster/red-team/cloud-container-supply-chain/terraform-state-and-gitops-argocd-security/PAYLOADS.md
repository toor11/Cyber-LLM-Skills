# Verification Probes and Expected Differentials

> Sub-skill: [`terraform-state-and-gitops-argocd-security`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Backend configuration

```text
# The five lines that decide state exposure.
rg -n --no-heading -A8 'backend\s+"' -g '*.tf' | rg -n "bucket|key|encrypt|kms_key_id|dynamodb_table|resource_group|container"
# OpenTofu native encryption, if present.
rg -n --no-heading -A10 "encryption\s*\{" -g '*.tf'
```

Expected differential: `encrypt = true` with `kms_key_id` and a lock table is the control; a backend block with none of the three is the finding, and the missing lines are the citation.

## Class 2 — State readability probe

```text
# Who can read the state object? (Do not download it.)
aws s3api get-bucket-policy --bucket "$STATE_BUCKET" --query Policy --output text | jq -r '.Statement[]|"\(.Principal) \(.Action)"'
aws s3api head-object --bucket "$STATE_BUCKET" --key "prod/terraform.tfstate" --query '{size:ContentLength,kms:SSEKMSKeyId,enc:ServerSideEncryption}'
```

Expected differential: a policy naming only the pipeline role plus `SSEKMSKeyId` set is the control; a wildcard or broad principal, or no `SSEKMSKeyId`, is the finding.

## Class 3 — AppProject scope

```text
kubectl get appprojects -n argocd -o json | jq -r '.items[] | "\(.metadata.name) src=\(.spec.sourceRepos) dst=\(.spec.destinations) cluster=\(.spec.clusterResourceWhitelist // [])"'
```

Expected differential: `src=["*"]` or a `clusterResourceWhitelist` entry is the finding; named repositories with namespace patterns and an empty cluster whitelist is the control.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
