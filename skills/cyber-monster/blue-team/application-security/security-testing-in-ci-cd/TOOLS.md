# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`security-testing-in-ci-cd`](SKILL.md) | Family: **Application Security**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `actionlint` | `actionlint -shellcheck= -oneline .github/workflows/*.yml` | Catch expression and shellcheck issues in workflow files offline | Cross-platform |
| `zizmor` | `zizmor .github/workflows/` | Audit workflows for injection, unpinned actions and token scope | Cross-platform |
| `semgrep` | `semgrep scan --config p/github-actions --error` | Policy checks over workflow YAML as source | Cross-platform |
| `cosign` | `cosign verify-attestation --type slsaprovenance --certificate-identity https://github.com/ORG/REPO/.github/workflows/release.yml@refs/heads/main IMAGE@sha256:...` | Verify the artefact you deploy was built by the workflow you think | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```bash
#!/usr/bin/env bash
# Gate-liveness evidence: lint the workflows, then prove the gate can fail.
set -euo pipefail
zizmor --format plain .github/workflows/
actionlint .github/workflows/*.yml
printf 'gate probe: expecting a non-zero exit from the security stage\n'
if semgrep scan --config p/owasp-top-ten --error tests/fixtures/planted_eval.py; then
  echo "FAIL: gate did not fire on planted defect"; exit 1
fi
echo "OK: gate fired as expected"
```

## Verification

- The planted-defect scan exits non-zero; a zero exit means the ruleset no longer covers the class and the gate is stale.
- `zizmor` reports no high-confidence injection findings, which is the check that would have caught an interpolated PR title.
- Re-run after pinning actions to commit SHAs; the pinning finding must disappear rather than being suppressed.
