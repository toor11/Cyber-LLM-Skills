# Verification Probes and Expected Differentials

> Sub-skill: [`cloud-recon-and-enumeration`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Identity and scope

```text
aws sts get-caller-identity --output json
az account show --output json | jq '{tenant:tenantId, sub:id, user:user.name}'
gcloud config list --format=json | jq '{project:.core.project, account:.core.account}'
```

Expected differential: a role ARN in a known account fixes the inventory scope; an unexpected account means the credential is broader than assumed and the report says so first.

## Class 2 — Permission-boundary differential

```text
# One allowed and one denied call per resource class bound the permission set.
aws s3 ls 2>&1 | head -2
aws s3api get-bucket-location --bucket "$KNOWN" 2>&1 | head -2
aws ec2 describe-instances --max-items 1 2>&1 | head -2
aws iam list-users --max-items 1 2>&1 | head -2
```

Expected differential: the pattern of successes and `AccessDenied`s is the boundary; a class where both succeed means read is unrestricted, and one where both fail means the class is closed.

## Class 3 — Public metadata

```text
# Certificate transparency and DNS, no credentials required.
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' | sort -u | head -20
dig +short "$DOMAIN" MX TXT NS
```

Expected differential: internal-looking names in CT output are the finding; only public service names is the control. Report the names, not the enumeration technique.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
