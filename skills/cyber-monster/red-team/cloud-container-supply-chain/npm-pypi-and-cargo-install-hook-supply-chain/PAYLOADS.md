# Verification Probes and Expected Differentials

> Sub-skill: [`npm-pypi-and-cargo-install-hook-supply-chain`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Install-command inventory

```text
rg -n --no-heading "npm (ci|install)|yarn (install|add)|pnpm (install|i)|pip install|poetry install|cargo (build|install)" .github/workflows/ .gitlab-ci.yml Jenkinsfile 2>/dev/null
rg -n --no-heading "ignore-scripts" .github/workflows/ .npmrc 2>/dev/null || echo "no ignore-scripts anywhere"
```

Expected differential: `--ignore-scripts` present on every install is the control; its absence on a job with credentials is the finding, and the rg output is the citation.

## Class 2 — Runnable-script enumeration

```text
# Which lifecycle scripts would run? No install, no execution.
python - <<'NPMPYPIANDCARG2B25_CLASS2'
import json, pathlib  # npm-pypi-and-cargo-install-hook-supply-chain: class 2 runnablescript enumeration
for lock in pathlib.Path(".").rglob("package-lock.json"):  # npm-pypi-and-cargo-install-hook-supply-chain: class 2 runnablescript enumeration
    data = json.loads(lock.read_text())
    for name, meta in data.get("packages", {}).items():
        if not name or not meta.get("hasInstallScript"):
            continue
        print(lock.parent.name, name, meta.get("version"))
NPMPYPIANDCARG2B25_CLASS2
```

Expected differential: an empty list means no dependency declares an install script; a non-empty list names the exact packages whose code would execute, which is the review scope.

## Class 3 — Credential-scope probe

```text
# What could a postinstall script read from this runner? List names, never values.
env | cut -d= -f1 | rg -i "TOKEN|KEY|SECRET|AWS|AZURE|GCP|NPM" | sort
ls -la ~/.npmrc ~/.aws/credentials ~/.config/gcloud 2>/dev/null
```

Expected differential: only the platform's own short-lived variables is the control; a named cloud key or a publish token is the blast radius, and the finding is the pair of facts together.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
