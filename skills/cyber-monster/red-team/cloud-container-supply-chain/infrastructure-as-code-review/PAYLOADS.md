# Verification Probes and Expected Differentials

> Sub-skill: [`infrastructure-as-code-review`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Declaration and effective-value comparison

```text
terraform init -backend=false >/dev/null 2>&1
terraform validate
checkov -d . --framework terraform --compact --quiet 2>/dev/null | tail -20
rg -n --no-heading "storage_encrypted|publicly_accessible|encrypted\s*=|acl\s*=|public_access" -g '*.tf'
```

Expected differential: a scanner hit on a property the module already sets safely is noise; a hit on a property the call site overrides is the finding, and the override line is the citation.

## Class 2 — Plan inspection

```text
terraform plan -out=/tmp/tf.plan -input=false >/dev/null
terraform show -json /tmp/tf.plan > /tmp/tf.json
jq -r '.resource_changes[] | select(.change.actions|index("delete") or index("create")) | "\(.address) \(.change.actions|join("+"))"' /tmp/tf.json
```

Expected differential: in-place `["update"]` on a security property is a review item; `["delete","create"]` on a resource holding data is a different finding, and the plan names it before the apply happens.

## Class 3 — Drift detection

```text
terraform plan -detailed-exitcode -input=false >/dev/null; echo "exit=$?"
# 0 = no drift, 2 = drift, 1 = error
terraform state list | head -20
```

Expected differential: exit 0 means declaration and state agree; exit 2 with a plan showing changes means the estate differs from the code, and the diff is the drift.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
