# Verification Probes and Expected Differentials

> Sub-skill: [`secrets-hunting-and-source-leak`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Working-tree and history scan

```text
# Working tree first, then history. The history pass is the one people skip.
gitleaks detect --source . --no-git --report-format json --report-path /tmp/wt.json
gitleaks detect --source . --report-format json --report-path /tmp/hist.json
jq -r '.[] | "\(.File):\(.StartLine) \(.RuleID) \(.Match[:40])"' /tmp/hist.json | head -20
```

Expected differential: a `RuleID` matching a provider prefix with a `StartLine` in the working tree is current exposure; the same rule only in history is historical exposure. Both need rotation; only the first needs immediate revocation.

## Class 2 — Image-layer scan

```text
# Credentials inside image layers, including deleted files.
docker save "$IMAGE" -o /tmp/img.tar && mkdir -p /tmp/img && tar -xf /tmp/img.tar -C /tmp/img
for l in /tmp/img/*/layer.tar; do tar -tf "$l" 2>/dev/null | rg -i "\.env|id_rsa|\.npmrc|credentials" && echo "  ^ in $l"; done
```

Expected differential: a credential file in any layer is the finding, and the layer id tells you which build step introduced it. A clean image has no such paths in any layer.

## Class 3 — Read-only verification

```text
# Verify an AWS key pair without using it for anything else.
AWS_ACCESS_KEY_ID="$ID" AWS_SECRET_ACCESS_KEY="$SECRET" aws sts get-caller-identity --output json
# Verify a GitHub token's scope.
curl -s -H "Authorization: Bearer $TOKEN" https://api.github.com/user | jq '{login, scopes: .}' -c
```

Expected differential: a valid identity response proves the credential is live and names the principal; a 401 or `InvalidClientTokenId` means it is revoked and the finding is historical.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
