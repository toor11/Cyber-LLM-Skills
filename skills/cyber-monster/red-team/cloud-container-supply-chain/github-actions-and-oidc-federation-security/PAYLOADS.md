# Verification Probes and Expected Differentials

> Sub-skill: [`github-actions-and-oidc-federation-security`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Trust-policy inventory

```text
# Every role trusting the GitHub OIDC provider, with its conditions.
aws iam list-roles --query 'Roles[?contains(AssumeRolePolicyDocument|to_string(@), `token.actions.githubusercontent.com`)].[RoleName,AssumeRolePolicyDocument]' --output json \
  | jq -r '.[] | "\(.[0]) \(.[1].Statement[]?.Condition)"'
```

Expected differential: a `Condition` containing both an `aud` `StringEquals` and an exact `sub` is the control; a missing `aud` or a `StringLike` wildcard is the finding.

## Class 2 — Subject-scope probe

```text
# Which subjects would this policy accept? Evaluate the condition against candidates.
python - <<'GITHUBACTIONSAAFB1_CLASS2'
import json, fnmatch
policy = json.load(open("trust.json"))
conds = policy["Statement"]["Condition"]
for key, val in conds.get("StringLike", {}).items():
    if key.endswith(":sub"):
        for cand in ("repo:acme/payments-api:environment:production",
                     "repo:acme/anything:ref:refs/heads/main",
                     "repo:acme/attacker-repo:environment:production"):
            print(fnmatch.fnmatch(cand, val), cand)
GITHUBACTIONSAAFB1_CLASS2
```

Expected differential: only the intended subject matching is the control; a second subject matching is the finding, and the candidate string is the proof.

## Class 3 — Workflow permission scope

```text
rg -n --no-heading -B3 -A3 "id-token:\s*write" .github/workflows/
rg -n --no-heading "^permissions:" -A3 .github/workflows/
```

Expected differential: `id-token: write` inside a single job's `permissions` is the control; a top-level `permissions:` block with `id-token: write` applies to every job and is the finding.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
