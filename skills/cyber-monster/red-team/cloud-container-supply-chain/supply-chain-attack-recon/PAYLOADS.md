# Verification Probes and Expected Differentials

> Sub-skill: [`supply-chain-attack-recon`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Dependency-graph concentration

```text
# Maintainer count and dependent count per package in the estate's lockfiles.
python - <<'SUPPLYCHAINATT8C44_CLASS1'
import json, pathlib, collections
direct = collections.Counter()
for lock in pathlib.Path(".").rglob("package-lock.json"):  # supply-chain-attack-recon: class 1 dependencygraph concentration
    data = json.loads(lock.read_text(errors="ignore"))
    for name in data.get("packages", {}):
        if name.startswith("node_modules/"):
            direct[name.replace("node_modules/", "")] += 1
print("most-referenced:", direct.most_common(10))
SUPPLYCHAINATT8C44_CLASS1
```

Expected differential: a package referenced once in a leaf project is low value; a package referenced across every lockfile is the concentration point, and the report pairs it with its maintainer count from the registry.

## Class 2 — Publish-path exposure

```text
# What does a public workflow reveal about the build path?
rg -n --no-heading "runs-on:|secrets\.|registry|npm publish|twine upload|docker push" .github/workflows/ 2>/dev/null
```

Expected differential: a workflow that names a self-hosted runner label and a registry host gives an attacker the build path with no access; a workflow that uses hosted runners and OIDC gives less.

## Class 3 — Publish-history anomaly

```text
npm view @acme/critical-lib time --json 2>/dev/null | jq -r 'to_entries | sort_by(.value) | .[-6:][] | "\(.key) \(.value)"'
npm view @acme/critical-lib maintainers --json 2>/dev/null
```

Expected differential: a publish that does not follow the package's cadence, or a maintainer added just before it, is the anomaly worth investigating; a steady cadence with a stable maintainer list is the control.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
