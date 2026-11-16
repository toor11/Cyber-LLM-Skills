# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`cloud-incident-response-identity-containment`](SKILL.md) | Family: **Incident Response**

Verified entry points for identity containment. The inventory and verification commands are read-only; the two state-changing calls are marked and deliberately show their confirmation surface so they are not run by reflex. Never invent flags — confirm with `<cmd> --help`, because `aws iam` argument names and `az ad` subcommand paths change between CLI majors.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| AWS CLI (`iam`) | `aws iam list-access-keys --user-name <user> --query "AccessKeyMetadata[].[AccessKeyId,Status,CreateDate]" --output table` | Inventory every key on the principal with status and age before touching any of them | Any host with AWS credentials |
| AWS CLI (`iam`) | `aws iam get-role --role-name <role> --query "Role.AssumeRolePolicyDocument"` | Read the trust policy to find federation or cross-account re-entry paths | Any host with AWS credentials |
| AWS CLI (`iam`) | `aws iam update-access-key --user-name <user> --access-key-id <id> --status Inactive` | Deactivate a key without destroying it; reversible, and keeps the identifier for the case record | Any host with AWS credentials |
| AWS CLI (`iam`) | `aws iam put-role-policy --role-name <role> --policy-name AWSRevokeOlderSessions --policy-document file://revoke.json` | Attach the token-issue-time deny that terminates assumed-role sessions; `revoke.json` uses a `DateLessThan` condition on `aws:TokenIssueTime` | Any host with AWS credentials |
| Microsoft Graph | `Revoke-MgUserSignInSession -UserId <upn> -Confirm` | Issuer-side session and refresh-token revocation for federated principals | Any host with Graph access |
| Microsoft Graph | `Get-MgOauth2PermissionGrant -All -Filter "principalId eq '<objectId>'"` | Enumerate delegated grants that outlive password rotation | Any host with Graph access |
| `aws sts` | `aws sts get-caller-identity` | Confirm which principal the responder is actually using before and after containment | Any host with AWS credentials |

## Minimal Script Shape

The shape below inventories artifacts and verifies that a revocation deny is present and correctly scoped. It performs no revocation unless `APPLY=1`, and even then only attaches the deny policy — it never deletes a key, so the case record keeps every identifier.

```bash
#!/usr/bin/env bash
# identity-containment-check.sh - inventory + verify. APPLY=1 attaches the deny only.
set -euo pipefail

ROLE="${ROLE:?role name under containment}"
USER_NAME="${USER_NAME:?user whose keys are inventoried}"
APPLY="${APPLY:-0}"
CUTOFF="${CUTOFF_ISO:?ISO8601 token issue time to deny before}"

echo "== 0. responder identity (never contain your own path) =="
aws sts get-caller-identity --output json

echo "== 1. every key on the principal =="
aws iam list-access-keys --user-name "$USER_NAME" \
  --query "AccessKeyMetadata[].[AccessKeyId,Status,CreateDate]" --output table

echo "== 2. trust policy (re-entry paths live here) =="
aws iam get-role --role-name "$ROLE" \
  --query "Role.AssumeRolePolicyDocument" --output json

echo "== 3. current deny state on the role =="
aws iam list-role-policies --role-name "$ROLE" --output text

REVOKE_JSON=$(mktemp)
cat >"$REVOKE_JSON" <<JSON
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": { "DateLessThan": { "aws:TokenIssueTime": "${CUTOFF}" } }
  }
}
JSON

if [ "$APPLY" = "1" ]; then
  echo "== 4. applying session-revocation deny (reversible) =="
  aws iam put-role-policy --role-name "$ROLE" \
    --policy-name AWSRevokeOlderSessions \
    --policy-document "file://${REVOKE_JSON}"
else
  echo "== 4. dry run: deny document prepared, not applied =="
  cat "$REVOKE_JSON"
fi

echo "== 5. verification reminder =="
echo "Proof is an AccessDenied or an absence of success for sessions issued before ${CUTOFF}."
```

## Notes That Prevent Wrong Runs

- `update-access-key --status Inactive` is reversible and preserves the key identifier for the case record; `delete-access-key` is not, and destroys the identifier that the audit record references. Deactivate first, delete only after the incident window closes.
- The session-revocation deny applies to every user of the role, not only the actor, and takes roughly thirty seconds to propagate. Warn the workload owner before attaching it.
- `put-role-policy` requires `PutRolePolicy` on the role. A responder without it will read a permission error as a failed containment; verify the permission in advance, not during the incident.
- Roles created from IAM Identity Center permission sets cannot be edited directly; the session must be revoked from the identity centre instead, and an attempt on the role will fail without explaining why.
- Deleting a user does not terminate sessions the user already assumed, and re-creating the same name later does not restore the old trust. Treat user deletion as the last step, not the first.
- `aws sts get-caller-identity` before and after every containment step is the cheapest guard against locking yourself out; a responder who contains their own path cannot verify anything afterwards.
