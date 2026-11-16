# Verification Probes and Expected Differentials

> Sub-skill: [`ci-cd-and-dependency-attacks-dependency-confusion`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Resolver-configuration inventory

```text
rg -n --no-heading "registry=|@[a-z0-9-]+:registry|always-auth" .npmrc .yarnrc .yarnrc.yml 2>/dev/null
rg -n --no-heading "index-url|extra-index-url|trusted-host|require-hashes" pip.conf pyproject.toml requirements*.txt 2>/dev/null
rg -n --no-heading "source-replacement|registry\s*=" .cargo/config.toml NuGet.config 2>/dev/null
```

Expected differential: a scope mapped to exactly one registry is the control; a default registry with no scope mapping is the finding, and the line is the citation.

## Class 2 — Fallback probe (lab scope only)

```text
# Resolve an internal name with the internal registry unreachable, in a container
# with no network route to it. A success from the public registry is the finding.
npm view @acme-labs-probe/utils versions --registry=https://registry.npmjs.org/ 2>&1 | head -3
pip download acme-labs-probe-utils==1.4.2 --index-url https://pypi.org/simple 2>&1 | tail -3
```

Expected differential: `E404` means the public registry has no such name, which is the control for this lab scope; a version list means the name is resolvable publicly and the build would take it.

## Class 3 — Integrity-pin audit

```text
# Does the lock carry integrity hashes for every entry?
python - <<'CICDANDDEPENDE6979_CLASS3'
import json, pathlib  # ci-cd-and-dependency-attacks-dependency-confusion: class 3 integritypin audit
for p in pathlib.Path(".").rglob("package-lock.json"):
    data = json.loads(p.read_text())
    packs = data.get("packages", {})
    missing = [k for k, v in packs.items() if k and "integrity" not in v]
    print(p, "entries:", len(packs), "missing_integrity:", len(missing))
CICDANDDEPENDE6979_CLASS3
rg -c "--hash=sha256:" requirements*.txt 2>/dev/null || echo "no hashes in requirements"
```

Expected differential: zero missing-integrity entries and hashed requirements is the control; any missing entry is the finding, because the artifact can change under a fixed version.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
