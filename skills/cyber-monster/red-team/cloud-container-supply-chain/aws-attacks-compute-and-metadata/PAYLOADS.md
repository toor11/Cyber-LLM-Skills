# Verification Probes and Expected Differentials

> Sub-skill: [`aws-attacks-compute-and-metadata`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Metadata-option inventory

```text
# Token requirement and hop limit for every instance you can describe.
aws ec2 describe-instances --query 'Reservations[].Instances[].{id:InstanceId,lt:LaunchTemplate.LaunchTemplateId,meta:MetadataOptions}' --output json \
  | jq -r '.[] | "\(.id) tokens=\(.meta.HttpTokens) hop=\(.meta.HttpPutResponseHopLimit) endpoint=\(.meta.HttpEndpoint)"'
```

Expected differential: `tokens=required hop=1` is the control; `tokens=optional` or `hop=2` is the finding, named per instance.

## Class 2 — Endpoint-version probe

```text
# From the instance: does a plain GET answer with credentials? (lab instance only)
curl -s -m 2 -o /dev/null -w 'v1_get: %{http_code}\n' http://169.254.169.254/latest/meta-data/instance-id
TOKEN=$(curl -s -m 2 -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
curl -s -m 2 -o /dev/null -w 'v2_get: %{http_code}\n' \
  -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id
```

Expected differential: `v1_get: 401` means v1 is blocked, which is the control; `v1_get: 200` means a plain GET works and the finding is confirmed without any SSRF.

## Class 3 — User-data exposure

```text
# Does user data carry a secret? Read it only on an instance you own.
curl -s -m 2 -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 60" -o /tmp/tok
curl -s -m 2 -H "X-aws-ec2-metadata-token: $(cat /tmp/tok)" \
  http://169.254.169.254/latest/user-data | rg -i "password|secret|token|key=" | head -5
```

Expected differential: no matches means user data is clean; a match names the secret and proves the exposure path independently of SSRF.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
