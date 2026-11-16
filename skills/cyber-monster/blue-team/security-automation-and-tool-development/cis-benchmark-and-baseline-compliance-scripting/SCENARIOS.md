# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`cis-benchmark-and-baseline-compliance-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative compliance-audit failures, each with the artefact that proves the diagnosis.

## Case 1: Compliant on paper, permissive in practice

- **Surface & Preconditions:** an audit greps `/etc/ssh/sshd_config` for `PermitRootLogin no` and finds it.
- **Root cause & impact:** a later `Match` block or an included file sets `PermitRootLogin yes`, and the effective configuration permits it. The report says compliant; the host accepts root logins.
- **Verification & fix:** read `sshd -T`, which resolves precedence, and compare the effective value.

## Case 2: Unreadable check counted as a pass

- **Surface & Preconditions:** the auditor wraps each check in a broad `try/except` that defaults to a passing result.
- **Root cause & impact:** a permission error or missing binary silently marks dozens of controls compliant. This is the failure mode that makes compliance tooling actively harmful, because it manufactures assurance.
- **Verification & fix:** use a tri-state result and report `error` or `not_applicable` with a reason; assert in tests that a failing query never yields `pass`.

## Case 3: Benchmark upgrade broke the mapping

- **Surface & Preconditions:** the control table is written for one benchmark revision, and the fleet moves to the next.
- **Root cause & impact:** control IDs and expected values change between revisions, so the auditor either evaluates the wrong thing under a familiar ID or reports a large number of `not_applicable` results. Either way the report is not about the benchmark it names.
- **Verification & fix:** version the control table with the benchmark, and treat a benchmark upgrade as a code change with its own review.

## Case 4: The audit changed the host

- **Surface & Preconditions:** a check runs a remediation helper to "confirm the control can be applied".
- **Root cause & impact:** the audit is no longer read-only, so the next run reports compliance that the auditor itself created, and the host changed without a change record.
- **Verification & fix:** remove all mutating commands from the audit path; remediation belongs to a separate approved workflow.
