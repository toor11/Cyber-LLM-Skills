# Verification Probes and Expected Differentials

> Sub-skill: [`ci-cd-and-dependency-attacks`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Trigger and permission inventory

```text
# Every workflow trigger, and whether a permissions block exists.
rg -n --no-heading "^(on|permissions):|pull_request_target|workflow_run" .github/workflows/
# Actions referenced by tag rather than SHA.
rg -n --no-heading "uses:\s*[^@\s]+@v[0-9]" .github/workflows/
```

Expected differential: `pull_request` with `permissions: contents: read` is the control; `pull_request_target` with no permissions block and a tag-pinned action is the finding.

## Class 2 — Fork-authority probe

```text
# What can a fork PR reach? Inspect the workflow's event context and the checkout ref.
rg -n --no-heading -A4 "pull_request_target" .github/workflows/ | rg -n "ref:|secrets\.|permissions"
gh api "repos/$OWNER/$REPO/actions/permissions/workflow" --jq '{default:.["default_workflow_permissions"]}'
```

Expected differential: a fork PR path that references `secrets.` or checks out `head.sha` is the finding; the repository's default workflow permission of `read` narrows the blast radius and belongs in the report.

## Class 3 — Dependency integrity

```text
# Lockfile present, and install scripts disabled?
ls package-lock.json pnpm-lock.yaml yarn.lock 2>/dev/null
rg -n --no-heading "npm (ci|install)|yarn install|pip install" .github/workflows/
rg -n --no-heading "ignore-scripts|--require-hashes|--no-deps" .github/workflows/
```

Expected differential: `npm ci` with `--ignore-scripts` and a committed lockfile is the control; a bare `npm install` with no lockfile is the finding, and it is exactly the path a registry compromise uses.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
