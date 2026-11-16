# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`dependency-and-package-risk-review`](SKILL.md) | Family: **Application Security**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `osv-scanner` | `osv-scanner scan source -r .` or `osv-scanner scan image IMAGE@sha256:...` | Advisory matching against the resolved graph or image | Cross-platform |
| `syft` | `syft IMAGE@sha256:... -o cyclonedx-json > sbom.cdx.json` | SBOM from the actual artefact | Cross-platform |
| `slsa-verifier` | `slsa-verifier verify-image IMAGE@sha256:... --source-uri github.com/ORG/REPO` | Provenance check against the builder identity | Cross-platform |
| `npm` | `npm ci --ignore-scripts --audit=false` | Install exactly the lockfile, without running package hooks | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```bash
#!/usr/bin/env bash
# Evidence order: SBOM from the artefact, advisories against it, provenance last.
set -euo pipefail
IMG=${1:?image@sha256:digest}
syft "$IMG" -o cyclonedx-json > sbom.cdx.json
osv-scanner scan sbom sbom.cdx.json --format json > osv.json || true
python - <<'PY'
import json
d = json.load(open("osv.json"))
for res in d.get("results", []):
    for pkg in res.get("packages", []):
        for v in pkg.get("vulnerabilities", []):
            print(pkg["package"]["name"], pkg["package"]["version"], v["id"])
PY
slsa-verifier verify-image "$IMG" --source-uri github.com/ORG/REPO
```

## Verification

- The SBOM lists transitive packages, not only direct dependencies; a short SBOM means the scanner read the manifest instead of the artefact.
- Every printed advisory id resolves in OSV with a fixed version you can pin.
- `slsa-verifier` exits zero; a non-zero exit means the deployed digest was not built by the expected workflow and takes precedence over the advisory list.
