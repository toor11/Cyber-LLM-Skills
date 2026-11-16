# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`custom-secret-scanner-detector-engineering`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative secret-detection failures, each with the artifact that proves the diagnosis.

## Case 1: The scanner leaked the credential it found

- **Surface & Preconditions:** a custom detector prints `match.group(0)` into a CI log or writes it into a JSON report stored as a build artifact.
- **Root cause & impact:** the log is retained longer and read by more people than the repository was; the detection tool becomes the disclosure channel, and the finding must now be rotated even if the original commit is scrubbed.
- **Verification & fix:** emit `sha256(salt + secret)[:16]` plus path and line only, and assert in CI that the report does not contain the fixture secret string.

## Case 2: Every test fixture is a "credential"

- **Surface & Preconditions:** a rule matches `token = "..."`-shaped strings with no entropy floor or path allowlist.
- **Root cause & impact:** fixtures, docs, and examples dominate the findings, reviewers stop reading them, and the one real leak is buried; the team's response is usually to disable the rule entirely.
- **Verification & fix:** add an entropy floor sized to the token format and a path allowlist for tests/docs/examples, then verify with a placeholder fixture in the real shape that must stay silent.

## Case 3: Lockfile hashes reported as secrets

- **Surface & Preconditions:** an unstructured high-entropy detector runs across `package-lock.json` and minified bundles.
- **Root cause & impact:** base64 integrity hashes are indistinguishable from secrets by entropy alone, so hundreds of findings appear per dependency update.
- **Verification & fix:** require a contextual keyword (`token`, `secret`, `api_key`) within the match window, and add path exclusions for lockfiles and vendored bundles rather than raising entropy until real secrets slip through.

## Case 4: History scan reports the same secret fifty times

- **Surface & Preconditions:** `git log -p --all` is scanned and every subsequent diff context re-matches the line.
- **Root cause & impact:** the finding count is inflated and the ticket names an arbitrary commit, so the rotation owner cannot tell when the credential first appeared.
- **Verification & fix:** deduplicate by `secret_sha256_16`, attribute the earliest introducing commit, and report the commit count as blast-radius context.
