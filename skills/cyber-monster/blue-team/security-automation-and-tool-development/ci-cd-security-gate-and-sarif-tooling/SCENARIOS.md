# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ci-cd-security-gate-and-sarif-tooling`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative gate failures, each with the artifact that proves the diagnosis.

## Case 1: The gate blocked a documentation-only PR

- **Surface & Preconditions:** the workflow diffs against `origin/main`, but the job checks out a shallow clone where that ref resolves to a stale or unrelated commit.
- **Root cause & impact:** the changed-hunk set is wrong or empty, so every pre-existing finding appears to be on "changed" lines and the PR is blocked for debt it never touched. Developers learn to add `--no-verify`-style bypasses.
- **Verification & fix:** log the resolved base SHA in the job output and fetch the base ref explicitly (`git fetch --depth=200 origin <base>`), then re-run before adjusting policy.

## Case 2: A waiver quietly became permanent

- **Surface & Preconditions:** a `suppressions` entry was added with `status: accepted` and no `expires_at`.
- **Root cause & impact:** the finding is suppressed forever; the gate reports zero blocking findings on a repository that has never fixed the issue, and no reviewer sees it again.
- **Verification & fix:** require `properties.expires_at` on every waiver, fail the job when it is missing, and report expired waivers as unsuppressed.

## Case 3: Every run reports the same finding as new

- **Surface & Preconditions:** a custom scanner writes SARIF by hand without `partialFingerprints`.
- **Root cause & impact:** without a stable identity the gate cannot match the finding to the baseline, so `baselineState` is effectively always `new` and the same accepted risk blocks PRs repeatedly.
- **Verification & fix:** generate `primaryLocationLineHash`-style fingerprints (or let `upload-sarif` compute them from source) rather than weakening the severity threshold.

## Case 4: Green pipeline, no scan

- **Surface & Preconditions:** the scanner step crashes on a missing config and the wrapper exits with an empty finding list.
- **Root cause & impact:** "no findings" and "scan did not run" collapse into the same success path, so the control is absent exactly when the repository changed enough to break it.
- **Verification & fix:** separate exit codes for scanner failure (`2`) and findings (`1`), and assert that each scanner emitted a non-empty `runs` array before evaluating results.
